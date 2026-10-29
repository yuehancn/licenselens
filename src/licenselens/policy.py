"""Policy: turn a license verdict into a ship / don't-ship decision.

The judge answers "what license is this?". That is not the question a team
actually asks. They ask "can we ship this in our paid product, and what has to
be true if we do?". This module answers that, and it separates the two reasons a
dependency gets blocked, because they need completely different responses:

* **License risk** - the terms forbid or endanger commercial use.
  Fix: buy a commercial license, replace the dependency, or isolate it.
* **Hygiene risk** - no license at all, an unknown license, or a dead project.
  Fix: get written permission, or pin and vendor it. This one is the silent
  killer, because "no LICENSE file" reads as "free" to almost everyone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .judge import (
    COMMERCIAL_CONDITIONAL,
    COMMERCIAL_FORBIDDEN,
    COMMERCIAL_OK,
    COMMERCIAL_UNKNOWN,
    COPYLEFT_FILE,
    COPYLEFT_NETWORK,
    COPYLEFT_PROJECT,
    Verdict,
)


class Decision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return {"allow": 0, "review": 1, "block": 2}[self.value]


class RiskKind(str, Enum):
    LICENSE = "license"
    HYGIENE = "hygiene"
    MAINTENANCE = "maintenance"


@dataclass
class Finding:
    kind: RiskKind
    severity: Decision
    code: str
    message: str
    remedy: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
            "remedy": self.remedy,
        }


@dataclass
class Policy:
    """What the organisation is willing to accept.

    Defaults describe a company shipping closed-source software commercially,
    which is the strictest common case and the safe default.
    """

    name: str = "commercial-closed-source"
    allowed: frozenset[str] = frozenset(
        {"allowed"}
    )
    #: Treat weak copyleft as acceptable (dynamic linking only).
    allow_weak_copyleft: bool = True
    #: Treat strong copyleft as acceptable (i.e. the product is itself GPL).
    allow_strong_copyleft: bool = False
    #: Treat network copyleft as acceptable (i.e. the service is itself AGPL).
    allow_network_copyleft: bool = False
    #: Maximum days since last commit before flagging the dependency as stale.
    max_staleness_days: int = 730
    #: Require a patent grant for dependencies in patent-heavy domains.
    require_patent_grant: bool = False
    #: Distributing a binary counts more than using a service internally.
    distribution_model: str = "distributed"  # or "saas" or "internal"

    @classmethod
    def permissive_only(cls) -> "Policy":
        return cls(name="permissive-only", allow_weak_copyleft=False)

    @classmethod
    def saas(cls) -> "Policy":
        """SaaS deployment: GPL is fine (no distribution), AGPL is not."""
        return cls(
            name="saas",
            allow_weak_copyleft=True,
            allow_strong_copyleft=True,
            allow_network_copyleft=False,
            distribution_model="saas",
        )

    @classmethod
    def copyleft_ok(cls) -> "Policy":
        return cls(
            name="copyleft-ok",
            allow_weak_copyleft=True,
            allow_strong_copyleft=True,
            allow_network_copyleft=True,
        )


def evaluate(
    verdict: Verdict,
    policy: Policy,
    *,
    staleness_days: int | None = None,
    archived: bool = False,
) -> tuple[Decision, list[Finding]]:
    """Combine license terms, hygiene and maintenance into one decision."""
    findings: list[Finding] = []

    # -- hygiene first: an unknown license is worse than a known-bad one ------
    if verdict.spdx_id == "NONE":
        findings.append(
            Finding(
                kind=RiskKind.HYGIENE,
                severity=Decision.BLOCK,
                code="NO-LICENSE",
                message=(
                    "No license file: default copyright applies, so all rights are "
                    "reserved and commercial use is not permitted."
                ),
                remedy=(
                    "Get written permission from the author, or replace the dependency. "
                    "Do not treat a public repository as free to use."
                ),
            )
        )
    elif verdict.spdx_id in ("UNRECOGNIZED", "CUSTOM"):
        findings.append(
            Finding(
                kind=RiskKind.HYGIENE,
                severity=Decision.BLOCK,
                code="UNKNOWN-LICENSE",
                message=f"License could not be resolved automatically ({verdict.name}).",
                remedy="Read the license text manually before shipping.",
            )
        )
    elif not verdict.decisive:
        findings.append(
            Finding(
                kind=RiskKind.HYGIENE,
                severity=Decision.REVIEW,
                code="AMBIGUOUS-LICENSE",
                message=(
                    "Automatic match was ambiguous; the runner-up is close enough that "
                    "the answer may be wrong."
                ),
                remedy="Confirm by reading the license text, then pin the result.",
            )
        )

    # -- commercial terms ----------------------------------------------------
    if verdict.commercial == COMMERCIAL_FORBIDDEN:
        findings.append(
            Finding(
                kind=RiskKind.LICENSE,
                severity=Decision.BLOCK,
                code="NONCOMMERCIAL",
                message=(
                    "NonCommercial terms: commercial use requires a separate license "
                    "from the rights holder."
                ),
                remedy=(
                    "Buy a commercial license, replace the dependency, or get written "
                    "permission. Do not ship it in a paid product."
                ),
            )
        )

    if verdict.copyleft == COPYLEFT_NETWORK and not policy.allow_network_copyleft:
        findings.append(
            Finding(
                kind=RiskKind.LICENSE,
                severity=Decision.BLOCK,
                code="NETWORK-COPYLEFT",
                message=(
                    "AGPL-style network clause: serving this to users over a network "
                    "obliges you to offer the complete corresponding source."
                ),
                remedy=(
                    "Buy the vendor's commercial license (this is the standard dual-license "
                    "escape hatch), or isolate the component behind a process boundary and "
                    "get legal sign-off first."
                ),
            )
        )
    elif verdict.copyleft == COPYLEFT_PROJECT:
        if policy.distribution_model == "saas" and policy.allow_strong_copyleft:
            findings.append(
                Finding(
                    kind=RiskKind.LICENSE,
                    severity=Decision.ALLOW,
                    code="GPL-NO-DISTRIBUTION",
                    message=(
                        "GPL applies, but a SaaS deployment is not distribution, so the "
                        "source obligation is not triggered."
                    ),
                    remedy="Keep it server-side; do not ship the binary to customers.",
                )
            )
        elif not policy.allow_strong_copyleft:
            findings.append(
                Finding(
                    kind=RiskKind.LICENSE,
                    severity=Decision.BLOCK,
                    code="STRONG-COPYLEFT",
                    message=(
                        "Strong copyleft: distributing a derivative work obliges you to "
                        "release it under the same license."
                    ),
                    remedy=(
                        "Buy a commercial license, replace it, or move it behind a "
                        "network boundary (which then makes the AGPL question relevant)."
                    ),
                )
            )
    elif verdict.copyleft == COPYLEFT_FILE:
        if not policy.allow_weak_copyleft:
            findings.append(
                Finding(
                    kind=RiskKind.LICENSE,
                    severity=Decision.REVIEW,
                    code="WEAK-COPYLEFT",
                    message=(
                        "Weak copyleft: modified files must be published, though your "
                        "larger work can stay proprietary."
                    ),
                    remedy="Do not modify the covered files, or publish those modifications.",
                )
            )
        else:
            findings.append(
                Finding(
                    kind=RiskKind.LICENSE,
                    severity=Decision.ALLOW,
                    code="WEAK-COPYLEFT-DYNAMIC",
                    message="Weak copyleft is acceptable under the current policy.",
                    remedy="Link dynamically and do not modify the covered files.",
                )
            )

    if verdict.commercial == COMMERCIAL_CONDITIONAL and not findings:
        findings.append(
            Finding(
                kind=RiskKind.LICENSE,
                severity=Decision.REVIEW,
                code="CONDITIONAL",
                message="Commercial use is possible but carries conditions.",
                remedy="Confirm the obligations in the report are met.",
            )
        )

    if policy.require_patent_grant and not verdict.patent_grant:
        findings.append(
            Finding(
                kind=RiskKind.LICENSE,
                severity=Decision.REVIEW,
                code="NO-PATENT-GRANT",
                message="This license grants no patent rights.",
                remedy="Get an indemnity or a patent review for patent-heavy domains.",
            )
        )

    # -- maintenance ---------------------------------------------------------
    if archived:
        findings.append(
            Finding(
                kind=RiskKind.MAINTENANCE,
                severity=Decision.REVIEW,
                code="ARCHIVED",
                message="The repository is archived; no further fixes will arrive.",
                remedy="Pin the version and plan a replacement.",
            )
        )
    if staleness_days is not None and staleness_days > policy.max_staleness_days:
        findings.append(
            Finding(
                kind=RiskKind.MAINTENANCE,
                severity=Decision.REVIEW,
                code="STALE",
                message=(
                    f"No commits for {staleness_days} days, past the "
                    f"{policy.max_staleness_days}-day threshold."
                ),
                remedy=(
                    "Staleness is a compliance risk, not just a quality one: abandoned "
                    "projects do not fix security issues, and their license posture stops "
                    "being maintained."
                ),
            )
        )

    decision = Decision.ALLOW
    for finding in findings:
        if finding.severity.rank > decision.rank:
            decision = finding.severity
    return decision, findings


def summarize(decision: Decision, findings: list[Finding]) -> str:
    if decision == Decision.ALLOW:
        return "Shippable as-is under the current policy."
    blocking = [f for f in findings if f.severity == Decision.BLOCK]
    if decision == Decision.BLOCK:
        return blocking[0].message if blocking else "Blocked."
    return findings[0].message if findings else "Needs review."