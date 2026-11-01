"""SBOM input: the same decision, from a document somebody else produced.

``scan`` reads *your* manifests and asks "which declared dependency will hurt
me?". ``sbom`` reads a CycloneDX or SPDX document - the artefact a customer,
an acquirer or a procurement team actually sends you - and answers the same
question about a dependency tree you did not build yourself.

Three things make this different from ``scan``, and each is a real trap:

1. **``NONE`` and ``NOASSERTION`` are SPDX tokens, not typos.** They appear in
   almost every real document. Reporting them as "unrecognized expression"
   sends the reader looking for a typo instead of at the actual finding.

2. **A missing license in an SBOM is not proof of an unlicensed package.** In
   a repository audit, "no LICENSE file" is authoritative: we looked. In an
   SBOM, an empty license field usually means the generating scanner did not
   populate it. Treating the two the same produces dozens of false "all rights
   reserved" claims against packages that are plainly MIT. Missing data is a
   review item; a missing license in the *source* is a block.

3. **The same is true of a bare license name.** CycloneDX allows
   ``{"license": {"name": "BSD License"}}`` - prose, not an SPDX id. Guessing
   costs a legal error; blocking everything makes the tool useless on real
   Java SBOMs, where name-only entries are the norm. It is a review item, and
   the remedy is to map the name.

No network calls, no dependencies. Formats supported: CycloneDX 1.x JSON and
SPDX 2.2 / 2.3 / 3.0 JSON.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .judge import Verdict, judge, judge_expression
from .manifest import ManifestEntry
from .policy import Decision, Finding, Policy, RiskKind, evaluate


class SbomError(ValueError):
    """The file is not an SBOM this tool can read, and guessing is not an option."""


@dataclass
class SbomDocument:
    """One parsed document plus the decisions for every component in it."""

    format: str
    spec_version: str
    subject: str
    entries: list[ManifestEntry] = field(default_factory=list)
    #: Things about the document itself worth telling the reader: a truncated
    #: component list, a format we only partly understand, a skipped root.
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "format": self.format,
            "spec_version": self.spec_version,
            "subject": self.subject,
            "notes": list(self.notes),
            "entries": [e.to_dict() for e in self.entries],
        }


# ---------------------------------------------------------------------------
# Loading and format detection
# ---------------------------------------------------------------------------


def load_sbom(path: str | Path, policy: Policy | None = None) -> SbomDocument:
    path = Path(path)
    if not path.exists():
        raise SbomError(f"no such file: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise SbomError(
            f"{path.name} is not valid JSON (line {exc.lineno}: {exc.msg}). "
            "XML SBOMs are not read; convert with `cyclonedx-cli convert` or "
            "`spdx-tools`, or export JSON from the generating tool."
        ) from exc
    if not isinstance(data, dict):
        raise SbomError(f"{path.name} is JSON but not an object at the top level.")
    return parse_sbom(data, source=path.name, policy=policy)


def parse_sbom(data: dict, *, source: str = "<memory>",
               policy: Policy | None = None) -> SbomDocument:
    """Detect the format, parse it, and classify every component."""
    policy = policy or Policy()

    if data.get("bomFormat") == "CycloneDX" or (
        "specVersion" in data and "components" in data
    ):
        doc = _from_cyclonedx(data, source)
    elif str(data.get("spdxVersion", "")).startswith("SPDX-2"):
        doc = _from_spdx2(data, source)
    elif "@graph" in data and _looks_like_spdx3(data):
        doc = _from_spdx3(data, source)
    else:
        raise SbomError(
            f"{source}: not a CycloneDX or SPDX JSON document. Neither "
            "`bomFormat: CycloneDX` nor `spdxVersion: SPDX-2.x` nor an SPDX 3.0 "
            "`@graph` is present, so the two formats that could be misread as "
            "each other are both excluded rather than guessed at."
        )

    for entry in doc.entries:
        _classify(entry, policy)
    return doc


def _looks_like_spdx3(data: dict) -> bool:
    graph = data.get("@graph")
    if not isinstance(graph, list):
        return False
    return any(
        isinstance(node, dict) and "spdxId" in node for node in graph
    )


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------

#: CycloneDX lets a component carry ``{"license": {"name": "..."}}`` - prose
#: instead of an SPDX id. Only names that state their own version are mapped;
#: ``"BSD License"`` or ``"GNU Lesser General Public License"`` cannot be
#: resolved without guessing which variant is meant, and guessing here means
#: telling someone AGPL is fine when the file said LGPL.
_NAME_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^apache license,?\s*(?:version\s*)?2\.0$", re.I), "Apache-2.0"),
    (re.compile(r"^the mit license(?:\s*\(mit\))?$", re.I), "MIT"),
    (re.compile(r"^mit license$", re.I), "MIT"),
    (re.compile(r"^bsd 2-clause(?:\s+\"simplified\")?\s+license$", re.I),
     "BSD-2-Clause"),
    (re.compile(r"^bsd 3-clause(?:\s+\"new\" or \"revised\")?\s+license$", re.I),
     "BSD-3-Clause"),
    (re.compile(r"^eclipse public license\s*-?\s*v?2\.0$", re.I), "EPL-2.0"),
    (re.compile(r"^mozilla public license,?\s*(?:v\.?\s*)?2\.0$", re.I), "MPL-2.0"),
    (re.compile(r"^isc license$", re.I), "ISC"),
)


def _resolve_license_name(name: str) -> str:
    """Map an unambiguous CycloneDX license *name* to its SPDX id, or give up."""
    cleaned = name.strip().strip("\"'")
    for pattern, spdx_id in _NAME_PATTERNS:
        if pattern.match(cleaned):
            return spdx_id
    return ""


def _from_cyclonedx(data: dict, source: str) -> SbomDocument:
    metadata = data.get("metadata") or {}
    root = metadata.get("component") or {}
    doc = SbomDocument(
        format="cyclonedx",
        spec_version=str(data.get("specVersion", "unknown")),
        subject=str(root.get("name") or data.get("metadata", {}).get("component", {}).get("name") or source),
    )
    entries: list[ManifestEntry] = []
    # A component may nest further components (CycloneDX 1.5 assemblies); a
    # reader that only looks at the top level silently drops most of a large
    # BOM, which reads as "everything is fine".
    _walk_cdx(data.get("components") or [], entries, source, depth=0, doc=doc)
    doc.entries = entries
    if not entries:
        doc.notes.append("the document lists no components")
    return doc


def _walk_cdx(components, entries: list[ManifestEntry], source: str, *,
              depth: int, doc: SbomDocument) -> None:
    if depth > 6:
        doc.notes.append("components nested deeper than 6 levels were not read")
        return
    for component in components:
        if not isinstance(component, dict):
            continue
        entries.append(_cdx_entry(component, source))
        nested = component.get("components")
        if isinstance(nested, list) and nested:
            _walk_cdx(nested, entries, source, depth=depth + 1, doc=doc)


def _cdx_entry(component: dict, source: str) -> ManifestEntry:
    purl = str(component.get("purl") or component.get("bom-ref") or "")
    ecosystem = ""
    if purl.startswith("pkg:"):
        ecosystem = purl[4:].split("/", 1)[0]
    group = str(component.get("group") or "")
    name = str(component.get("name") or "<unnamed>")
    if group and not name.startswith(group):
        name = f"{group}/{name}"
    entry = ManifestEntry(
        name=name,
        version_spec=str(component.get("version") or ""),
        ecosystem=ecosystem,
        source_file=source,
        purl=purl,
    )
    declared, kind, note = _cdx_license(component.get("licenses"))
    entry.license_declared = declared
    entry.note = note
    entry.license_kind = kind
    return entry


def _cdx_license(licenses) -> tuple[str, str, str]:
    """Flatten CycloneDX's two license shapes into one expression.

    ``{"expression": "MIT OR Apache-2.0"}`` is already an SPDX expression.
    A list of ``{"license": {...}}`` objects has no operator, and CycloneDX
    defines the list as cumulative, so the items are joined with AND - the
    conservative reading, and the one the spec's own guidance implies.
    """
    if not isinstance(licenses, list) or not licenses:
        return "", "missing", ""

    for item in licenses:
        if isinstance(item, dict) and isinstance(item.get("expression"), str):
            return item["expression"].strip(), "expression", "cyclonedx expression"

    ids: list[str] = []
    unresolved: list[str] = []
    for item in licenses:
        if not isinstance(item, dict):
            continue
        inner = item.get("license") or {}
        spdx_id = str(inner.get("id") or "").strip()
        if spdx_id:
            ids.append(spdx_id)
            continue
        name = str(inner.get("name") or "").strip()
        if not name:
            continue
        mapped = _resolve_license_name(name)
        if mapped:
            ids.append(mapped)
        else:
            unresolved.append(name)

    if ids and unresolved:
        # Partly resolvable: keep what we know, and say what we did not use.
        return " AND ".join(ids), "id", (
            "unmapped license names: " + " / ".join(sorted(set(unresolved)))
        )
    if ids:
        return " AND ".join(ids), "id", ""
    if unresolved:
        return unresolved[0], "name", (
            "license given as a name, not an SPDX id, and it does not state "
            "which variant it means"
        )
    return "", "missing", ""


# ---------------------------------------------------------------------------
# SPDX 2.2 / 2.3
# ---------------------------------------------------------------------------

#: The two tokens the SPDX spec reserves so that "no license" and "we did not
#: look" cannot be confused with a real id.
_SPDX_SENTINELS = {"NONE", "NOASSERTION"}


def _from_spdx2(data: dict, source: str) -> SbomDocument:
    doc = SbomDocument(
        format="spdx",
        spec_version=str(data.get("spdxVersion", "SPDX-2.x")),
        subject=str(data.get("name") or source),
    )
    packages = data.get("packages") or []
    if not isinstance(packages, list):
        raise SbomError(f"{source}: `packages` is not a list")

    for package in packages:
        if not isinstance(package, dict):
            continue
        entry = ManifestEntry(
            name=str(package.get("name") or "<unnamed>"),
            version_spec=str(package.get("versionInfo") or ""),
            ecosystem=_ecosystem_from_refs(package.get("externalRefs")),
            source_file=source,
            purl=_purl_from_refs(package.get("externalRefs")),
        )
        declared, note = _pick_spdx_license(
            package.get("licenseConcluded"), package.get("licenseDeclared")
        )
        entry.license_declared = declared
        entry.note = note
        entry.license_kind = "id" if declared else "missing"
        doc.entries.append(entry)

    if not doc.entries:
        doc.notes.append("the document lists no packages")
    return doc


def _pick_spdx_license(concluded, declared) -> tuple[str, str]:
    """Prefer the concluded license, but never let a sentinel hide a real one.

    ``licenseConcluded: NOASSERTION`` next to ``licenseDeclared: MIT`` is the
    most common shape in the wild: the scanner declined to conclude anything
    while the package itself states its license. Taking the sentinel at face
    value reports MIT packages as unknown.
    """
    concluded = str(concluded or "").strip()
    declared = str(declared or "").strip()

    if concluded and concluded.upper() not in _SPDX_SENTINELS:
        note = ""
        if declared and declared.upper() in _SPDX_SENTINELS:
            note = f"declared was {declared}"
        return concluded, note
    if declared and declared.upper() not in _SPDX_SENTINELS:
        return declared, "concluded was not usable, declared used"
    if concluded.upper() in _SPDX_SENTINELS or declared.upper() in _SPDX_SENTINELS:
        return "", f"both license fields are {concluded or declared}"
    return "", ""


def _purl_from_refs(refs) -> str:
    for ref in refs or []:
        if isinstance(ref, dict) and str(ref.get("referenceType", "")).lower() == "purl":
            return str(ref.get("referenceLocator") or "")
    return ""


def _ecosystem_from_refs(refs) -> str:
    purl = _purl_from_refs(refs)
    if purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0]
    return ""


# ---------------------------------------------------------------------------
# SPDX 3.0
# ---------------------------------------------------------------------------


def _from_spdx3(data: dict, source: str) -> SbomDocument:
    graph = [node for node in data.get("@graph") or [] if isinstance(node, dict)]
    doc = SbomDocument(
        format="spdx",
        spec_version="SPDX-3.0",
        subject=str(data.get("name") or source),
    )

    # License text lives on separate elements; packages point at them through
    # hasConcludedLicense / hasDeclaredLicense relationships. Inlining the
    # expression onto the package is what a human expects, so resolve the
    # indirection once and keep the two precedence rules the 2.x reader uses.
    expressions: dict[str, str] = {}
    for node in graph:
        if node.get("type") == "simplelicensing_LicenseExpression":
            value = node.get("simplelicensing_licenseExpression")
            if isinstance(value, str):
                expressions[str(node.get("spdxId", ""))] = value.strip()

    by_from: dict[str, dict[str, list[str]]] = {}
    for node in graph:
        if node.get("type") not in ("Relationship", "LifecycleScopedRelationship"):
            continue
        kind = str(node.get("relationshipType") or "")
        if kind not in ("hasConcludedLicense", "hasDeclaredLicense"):
            continue
        source_id = str(node.get("from") or "")
        targets = node.get("to") or []
        slot = by_from.setdefault(source_id, {"concluded": [], "declared": []})
        bucket = "concluded" if kind == "hasConcludedLicense" else "declared"
        for target in targets:
            text = expressions.get(str(target))
            if text:
                slot[bucket].append(text)

    for node in graph:
        node_type = str(node.get("type") or "")
        if not node_type.endswith("Package"):
            continue
        spdx_id = str(node.get("spdxId") or "")
        linked = by_from.get(spdx_id, {"concluded": [], "declared": []})
        concluded = " AND ".join(linked["concluded"])
        declared = " AND ".join(linked["declared"])
        license_text, note = _pick_spdx_license(concluded, declared)

        purl = ""
        for ref in node.get("externalRef") or []:
            if isinstance(ref, dict) and str(ref.get("type", "")).lower() == "purl":
                purl = str(ref.get("locator") or "")

        entry = ManifestEntry(
            name=str(node.get("name") or "<unnamed>"),
            version_spec=str(node.get("software_packageVersion") or ""),
            ecosystem=purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else "",
            source_file=source,
            purl=purl,
        )
        entry.license_declared = license_text
        entry.note = note
        entry.license_kind = "id" if license_text else "missing"
        doc.entries.append(entry)

    if not doc.entries:
        doc.notes.append("no software_Package elements in the @graph")
    return doc


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _classify(entry: ManifestEntry, policy: Policy) -> None:
    """One entry -> one decision, with the SBOM-specific leniency made explicit."""
    kind = entry.license_kind
    declared = (entry.license_declared or "").strip()

    if not declared:
        entry.decision = Decision.REVIEW
        entry.note = (entry.note + " | no license recorded").lstrip(" |")
        entry.findings = [
            Finding(
                kind=RiskKind.HYGIENE,
                severity=Decision.REVIEW,
                code="LICENSE-MISSING",
                message=(
                    "The SBOM records no license for this component. That is a gap "
                    "in the document, not evidence that the package is unlicensed."
                ),
                remedy=(
                    "Regenerate the SBOM with a scanner that resolves licenses, or "
                    "look the package up. Do not read this as 'unlicensed'."
                ),
            )
        ]
        return

    entry.verdict = judge_expression(declared)

    if entry.verdict.spdx_id == "UNRECOGNIZED" and kind == "name":
        # Prose that names a license without saying which variant. Neither
        # permissive nor blocked can be justified, and a block here would be
        # reported for every name-only entry in a Java SBOM.
        entry.decision = Decision.REVIEW
        entry.note = (entry.note + " | unmapped license name").lstrip(" |")
        entry.findings = [
            Finding(
                kind=RiskKind.HYGIENE,
                severity=Decision.REVIEW,
                code="LICENSE-NAME",
                message=(
                    f"The component names its license as {declared!r}, which is not "
                    "an SPDX identifier and does not state which variant is meant."
                ),
                remedy=(
                    "Map the name to an SPDX id (or read the license text) and record "
                    "the decision in a policy file. Guessing the variant is how LGPL "
                    "gets reported as GPL and vice versa."
                ),
            )
        ]
        return

    entry.decision, entry.findings = evaluate(entry.verdict, policy)


def classify_license_text(text: str, policy: Policy) -> tuple[Verdict, Decision, list[Finding]]:
    """Classify a license *document* (not an id) - used for SPDX extracted text."""
    verdict = judge(text)
    decision, findings = evaluate(verdict, policy)
    return verdict, decision, findings