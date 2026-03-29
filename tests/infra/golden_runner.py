"""Run a golden test for a P4Py program.

CLI usage: python golden_runner.py <module_path> <golden_file>

Compiles the P4Py program, emits P4-16 source, and compares it against
the golden file.
"""

from __future__ import annotations

import importlib
import sys

from p4py.compiler import compile
from p4py.emitter.p4 import emit


def run_golden_test(module_path: str, golden_path: str) -> bool:
    """Compile a P4Py program and compare emitted P4 against a golden file."""
    mod = importlib.import_module(module_path)
    program = compile(mod.main)
    actual = emit(program)

    with open(golden_path) as f:
        expected = f.read()

    if actual == expected:
        print("PASS: emitted P4 matches golden file")
        return True

    print("FAIL: emitted P4 does not match golden file")
    # Show first differing line for debugging.
    for i, (a, e) in enumerate(
        zip(actual.splitlines(), expected.splitlines()), start=1
    ):
        if a != e:
            print(f"  first difference at line {i}:")
            print(f"    expected: {e}")
            print(f"    actual:   {a}")
            break
    return False


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <module_path> <golden_file>", file=sys.stderr)
        sys.exit(2)
    if not run_golden_test(sys.argv[1], sys.argv[2]):
        sys.exit(1)


if __name__ == "__main__":
    main()
