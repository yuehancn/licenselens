"""Report renderers.

Four formats, each for a different consumer:

``table``   terminal, for the person running the audit
``markdown`` a pull-request comment or an appendix to a compliance doc
``csv``      a spreadsheet for whoever signs off
``sarif``    GitHub code scanning, so findings annotate files and fail the build

SARIF is the one that changes behaviour: a license problem that never appears in
the PR diff is a license problem nobody fixes.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone

from .policy import Decision, Finding
from .probe import RepoRecord

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_ICON = {Decision.ALLOW: "OK  ", Decision.REVIEW: "WARN", Decision.BLOCK: "FAIL"}


def _fmt_repo(record: RepoRecord) -> str:
    return record.repo[:40].ljust(40)


def render_table(records: list[RepoRecord], *, show_findings: bool = True) -> str:
    if not records:
        return "No repositories analysed."

    lines = [
        f"{'STATUS':<5} {'REPOSITORY':<40} {'LICENSE':<24} {'DECISION':<9} {'★':>8}",
        "-" * 90,
    ]
    for record in records:
        license_id = record.verdict.spdx_id if record.verdict else "-"
        stars = record.stars if record.stars is not None else "-"
        lines.append(
            f"{_ICON[record.decision]:<5} {_fmt_repo(record)} {license_id[:24]:<24} "
            f"{record.decision.value:<9} {stars:>8}"
        )

    counts = Counter(r.decision for r in records)
    lines.append("-" * 90)
    lines.append(
        f"{len(records)} repos: "
        f"{counts[Decision.ALLOW]} allow, "
        f"{counts[Decision.REVIEW]} review, "
        f"{counts[Decision.BLOCK]} block"
    )

    if show_findings:
        blocked = [r for r in records if r.decision == Decision.BLOCK]
        if blocked:
            lines.append("")
            lines.append("Blocking issues")
            for record in blocked:
                blocking = [f for f in record.findings if f.severity == Decision.BLOCK]
                for finding in blocking:
                    lines.append(f"  {record.repo}")
                    lines.append(f"    [{finding.code}] {finding.message}")
                    if finding.remedy:
                        lines.append(f"    -> {finding.remedy}")
    return "\n".join(lines)


def render_csv(records: list[RepoRecord]) -> str:
    buffer = io.StringIO()
    fieldnames = [
        "repo", "decision", "license", "commercial", "copyleft", "confidence",
        "decisive", "stars", "archived", "staleness_days", "license_file",
        "github_spdx", "blocking_codes", "notes",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for record in records:
        verdict = record.verdict
        writer.writerow({
            "repo": record.repo,
            "decision": record.decision.value,
            "license": verdict.spdx_id if verdict else "",
            "commercial": verdict.commercial if verdict else "",
            "copyleft": verdict.copyleft if verdict else "",
            "confidence": f"{verdict.confidence:.2f}" if verdict else "",
            "decisive": verdict.decisive if verdict else "",
            "stars": record.stars,
            "archived": record.archived,
            "staleness_days": record.staleness_days,
            "license_file": record.license_file,
            "github_spdx": record.github_spdx,
            "blocking_codes": ";".join(
                f.code for f in record.findings if f.severity == Decision.BLOCK
            ),
            "notes": ";".join(f.message for f in record.findings if f.severity != Decision.ALLOW)[:300],
        })
    return buffer.getvalue()


def render_markdown(records: list[RepoRecord], *, title: str = "License audit") -> str:
    counts = Counter(r.decision for r in records)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [
        f"# {title}",
        "",
        f"Generated {stamp} · {len(records)} repositories · "
        f"**{counts[Decision.BLOCK]} blocked**, {counts[Decision.REVIEW]} need review, "
        f"{counts[Decision.ALLOW]} clear",
        "",
        "| Decision | Repository | License | Commercial | Why |",
        "| --- | --- | --- | --- | --- |",
    ]
    for record in records:
        verdict = record.verdict
        reason = ""
        severe = [f for f in record.findings if f.severity == record.decision]
        if severe:
            reason = severe[0].message.replace("|", "/")
        out.append(
            f"| {record.decision.value} | `{record.repo}` | "
            f"{verdict.spdx_id if verdict else '-'} | "
            f"{verdict.commercial if verdict else '-'} | {reason[:120]} |"
        )

    blocked = [r for r in records if r.decision == Decision.BLOCK]
    if blocked:
        out += ["", "## What to do about the blocked ones", ""]
        for record in blocked:
            out.append(f"### `{record.repo}`")
            for finding in record.findings:
                if finding.severity != Decision.BLOCK:
                    continue
                out.append(f"- **{finding.code}** — {finding.message}")
                if finding.remedy:
                    out.append(f"  - Fix: {finding.remedy}")
            out.append("")
    return "\n".join(out)


#: SARIF severity mapping. ``error`` fails a required check; ``warning`` shows
#: up in the Security tab without blocking.
_SARIF_LEVEL = {Decision.BLOCK: "error", Decision.REVIEW: "warning", Decision.ALLOW: "note"}


def render_sarif(records: list[RepoRecord]) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for record in records:
        for finding in record.findings:
            if finding.severity == Decision.ALLOW:
                continue
            if finding.code not in rules:
                rules[finding.code] = {
                    "id": finding.code,
                    "name": _rule_name(finding.code),
                    "shortDescription": {"text": finding.message[:200]},
                    "help": {"text": finding.remedy or finding.message},
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL[finding.severity],
                    },
                    "properties": {"kind": finding.kind.value, "tags": ["license", "compliance"]},
                }
            results.append({
                "ruleId": finding.code,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {
                    "text": f"{record.repo}: {finding.message}"
                    + (f" Remedy: {finding.remedy}" if finding.remedy else "")
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "package.json"},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"fullyQualifiedName": record.repo}],
                }],
                "properties": {
                    "repo": record.repo,
                    "license": record.verdict.spdx_id if record.verdict else "",
                    "decision": record.decision.value,
                },
            })

    payload = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "licenselens",
                    "informationUri": "https://github.com/yuehancn/licenselens",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {
                "generated": datetime.now(timezone.utc).isoformat(),
                "repositories": len(records),
            },
        }],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _rule_name(code: str) -> str:
    return "".join(part.capitalize() for part in code.split("-"))


def render_json(records: list[RepoRecord], meta: dict | None = None) -> str:
    return json.dumps(
        {
            "meta": meta or {},
            "records": [r.to_dict() for r in records],
        },
        indent=2,
        ensure_ascii=False,
    )


RENDERERS = {
    "table": render_table,
    "csv": render_csv,
    "markdown": render_markdown,
    "md": render_markdown,
    "sarif": render_sarif,
    "json": render_json,
}


def render(records: list[RepoRecord], fmt: str, **kwargs) -> str:
    renderer = RENDERERS.get(fmt.lower())
    if renderer is None:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(RENDERERS)}")
    return renderer(records, **kwargs)


def exit_code(records: list[RepoRecord]) -> int:
    """CI-friendly: 1 when anything is blocked."""
    return 1 if any(r.decision == Decision.BLOCK for r in records) else 0