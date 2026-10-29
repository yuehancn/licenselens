#!/usr/bin/env python
"""Run licenselens straight from a git checkout, no install required.

``pip install`` is not always possible (locked-down CI, air-gapped review
machines, corporate proxies). This launcher makes ``python licenselens.py ...``
work identically to the installed console script, so the tool is usable the
moment the repository is cloned.

The same file doubles as a test entry point: ``python licenselens.py selftest``
runs the regression suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    argv = sys.argv[1:]

    if argv and argv[0] in ("selftest", "test"):
        sys.path.insert(0, str(ROOT / "tests"))
        # The test module registers its cases as an import side effect, so it
        # must be imported before the runner looks at the registry. Skipping
        # this import made ``selftest`` report a convincing "0/0 passed".
        import test_all  # noqa: F401
        from _runner import main as run_tests

        return run_tests(argv[1:])

    from licenselens.cli import main as cli_main

    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())