"""Zero-dependency test runner.

``licenselens`` ships no runtime dependencies, and its test suite should not
require any either: the whole point of the tool is that it runs on a locked-down
machine where ``pip install`` is not an option. This runner gives us
``pytest``-style ergonomics (``@case``, assertions, parametrisation) in about a
hundred lines of stdlib, so ``python tests/run_tests.py`` just works.

Run with ``-v`` for per-case output, or pass a substring to filter.
"""

from __future__ import annotations

import sys
import traceback
from typing import Callable

_REGISTRY: list[tuple[str, Callable[[], None]]] = []


def case(func: Callable[[], None]) -> Callable[[], None]:
    _REGISTRY.append((func.__name__, func))
    return func


class _Param:
    def __init__(self, values: list[tuple]) -> None:
        self.values = values

    def __call__(self, func: Callable[..., None]) -> Callable[..., None]:
        for index, args in enumerate(self.values):
            if not isinstance(args, tuple):
                args = (args,)
            label = f"{func.__name__}[{index}]"
            _REGISTRY.append((label, _bind(func, args)))
        return func


def parametrize(values: list[tuple]) -> _Param:
    return _Param(values)


def _bind(func: Callable, args: tuple) -> Callable[[], None]:
    def runner() -> None:
        func(*args)

    runner.__name__ = func.__name__
    return runner


def raises(exc_type: type[BaseException], func: Callable, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except exc_type as exc:
        return exc
    raise AssertionError(f"expected {exc_type.__name__}, nothing was raised")


class approx:
    def __init__(self, expected: float, tol: float = 1e-6) -> None:
        self.expected = expected
        self.tol = tol

    def __eq__(self, other: object) -> bool:
        return abs(float(other) - self.expected) <= self.tol  # type: ignore[arg-type]

    def __repr__(self) -> str:
        return f"approx({self.expected})"


def run(filter_text: str = "", verbose: bool = False) -> int:
    passed = failed = 0
    failures: list[tuple[str, str]] = []
    for name, func in _REGISTRY:
        if filter_text and filter_text not in name:
            continue
        try:
            func()
            passed += 1
            if verbose:
                print(f"  PASS  {name}")
        except Exception:  # noqa: BLE001 - a test failure is any exception
            failed += 1
            failures.append((name, traceback.format_exc()))
            print(f"  FAIL  {name}")

    print()
    for name, tb in failures:
        print(f"---- {name} " + "-" * max(0, 60 - len(name)))
        print(tb)
    total = passed + failed
    print(f"{passed}/{total} passed" + (f", {failed} failed" if failed else ""))
    return 0 if failed == 0 else 1


def main(argv: list[str]) -> int:
    verbose = "-v" in argv
    filters = [a for a in argv if not a.startswith("-")]
    return run(filters[0] if filters else "", verbose)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))