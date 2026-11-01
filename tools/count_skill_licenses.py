"""Count license coverage across a local skill tree.

Written for the 2026-10-30 article: the claim "my own 38 skills have no license"
has to be reproducible by the reader, not just asserted. Prints counts only, so
it is safe to paste the output.

    python count_skill_licenses.py C:/Users/yuehancn/.workbuddy/skills
"""

from __future__ import annotations

import sys
from pathlib import Path

LICENSE_NAMES = ("license", "licence", "copying", "notice")


def has_license(directory: Path) -> str:
    """Return the licence file name if one exists at the top of the skill."""
    try:
        for entry in directory.iterdir():
            if entry.is_file() and entry.name.lower().split(".")[0] in LICENSE_NAMES:
                return entry.name
    except OSError:
        pass
    return ""


def main(argv: list[str]) -> int:
    root = Path(argv[0]) if argv else Path(".")
    if not root.exists():
        print(f"no such path: {root}", file=sys.stderr)
        return 2

    skills = sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith("_"))
    with_license = [(p.name, has_license(p)) for p in skills]
    licensed = [(n, f) for n, f in with_license if f]
    missing = [n for n, f in with_license if not f]

    print(f"skills          : {len(skills)}")
    print(f"with a LICENSE  : {len(licensed)}")
    print(f"without         : {len(missing)}")
    if licensed:
        print("\nlicensed:")
        for name, fname in licensed:
            print(f"  {name:<34} {fname}")
    if missing:
        print("\nno license file:")
        for name in missing:
            print(f"  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))