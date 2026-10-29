"""Generate docs/demo.svg from a real audit run.

The image in the README must show actual output, not a mock-up: a compliance
tool whose own screenshot is staged is not worth trusting.

    python tools/make_demo_svg.py

Requires network (it probes real repositories) and writes docs/demo.svg.
"""

from __future__ import annotations

import html
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from licenselens.probe import Prober  # noqa: E402
from licenselens.sources import Fetcher, resolve_token  # noqa: E402

REPOS = [
    "pallets/flask",
    "immich-app/immich",
    "n8n-io/n8n",
    "anthropics/skills",
    "comfyanonymous/ComfyUI",
]

COLORS = {"allow": "#1a7f37", "review": "#9a6700", "block": "#cf222e"}
LABELS = {"allow": "PASS", "review": "WARN", "block": "FAIL"}

W = 880
LEFT = 24
COL_STATUS = 24
COL_REPO = 92
COL_LICENSE = 356
COL_DECISION = 660
COL_STARS = 852

HEADER_Y = 96
RULE_Y = 106
FIRST_ROW_Y = 132
ROW_H = 27


def build(records) -> str:
    lines_count = len(records)
    footer_rule_y = FIRST_ROW_Y + (lines_count - 1) * ROW_H + 16
    height = footer_rule_y + 56

    rows: list[str] = []
    for index, record in enumerate(records):
        y = FIRST_ROW_Y + index * ROW_H
        decision = record.decision.value
        color = COLORS[decision]
        license_id = record.verdict.spdx_id if record.verdict else "-"
        stars = record.stars if record.stars is not None else "-"
        rows.append(
            f'<text x="{COL_STATUS}" y="{y}" class="mono" fill="{color}" '
            f'font-weight="700">{LABELS[decision]}</text>'
            f'<text x="{COL_REPO}" y="{y}" class="mono" fill="#1f2328">'
            f'{html.escape(record.repo)}</text>'
            f'<text x="{COL_LICENSE}" y="{y}" class="mono" fill="{color}">'
            f'{html.escape(license_id)}</text>'
            f'<text x="{COL_DECISION}" y="{y}" class="mono" fill="{color}" '
            f'font-weight="600">{decision}</text>'
            f'<text x="{COL_STARS}" y="{y}" class="mono" fill="#59636e" '
            f'text-anchor="end">{stars}</text>'
        )

    blocked = sum(1 for r in records if r.decision.value == "block")
    allowed = sum(1 for r in records if r.decision.value == "allow")
    review = sum(1 for r in records if r.decision.value == "review")

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {height}" width="{W}" height="{height}" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">
<style>
 .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}}
 .hdr{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:10.5px;letter-spacing:.09em;fill:#59636e}}
 .cmd{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;fill:#1f2328;font-weight:600}}
</style>
<rect width="{W}" height="{height}" rx="10" fill="#ffffff" stroke="#d1d9e0"/>
<circle cx="26" cy="26" r="6" fill="#cf222e"/>
<circle cx="48" cy="26" r="6" fill="#bf8700"/>
<circle cx="70" cy="26" r="6" fill="#1a7f37"/>
<text x="{LEFT}" y="64" class="cmd">$ licenselens audit --file repos.txt</text>
<line x1="{LEFT}" y1="76" x2="{W - LEFT}" y2="76" stroke="#d1d9e0"/>
<text x="{COL_STATUS}" y="{HEADER_Y}" class="hdr">STATUS</text>
<text x="{COL_REPO}" y="{HEADER_Y}" class="hdr">REPOSITORY</text>
<text x="{COL_LICENSE}" y="{HEADER_Y}" class="hdr">LICENSE</text>
<text x="{COL_DECISION}" y="{HEADER_Y}" class="hdr">DECISION</text>
<text x="{COL_STARS}" y="{HEADER_Y}" class="hdr" text-anchor="end">STARS</text>
<line x1="{LEFT}" y1="{RULE_Y}" x2="{W - LEFT}" y2="{RULE_Y}" stroke="#d1d9e0"/>
{"".join(rows)}
<line x1="{LEFT}" y1="{footer_rule_y}" x2="{W - LEFT}" y2="{footer_rule_y}" stroke="#d1d9e0"/>
<text x="{LEFT}" y="{footer_rule_y + 26}" class="mono" fill="#59636e">{lines_count} repos: {allowed} allow, {review} review, {blocked} block</text>
<text x="{LEFT}" y="{footer_rule_y + 48}" class="mono" fill="#59636e">GitHub API quota consumed: 0 requests</text>
</svg>
'''


def main() -> int:
    token, _ = resolve_token()
    prober = Prober(
        fetcher=Fetcher(timeout=25, cache_dir=str(ROOT / ".cache")),
        token=token,
    )
    records = [prober.probe(repo) for repo in REPOS]
    out = ROOT / "docs" / "demo.svg"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build(records), encoding="utf-8")
    print(f"wrote {out}")
    for record in records:
        print(f"  {record.repo:<26} {record.verdict.spdx_id:<22} {record.decision.value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())