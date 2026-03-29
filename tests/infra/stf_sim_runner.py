"""Run an STF test through the P4Py simulator.

CLI usage: python -m tests.infra.stf_sim_runner <module_path> <stf_file>

Where <module_path> is a dotted Python path to a module containing a `main`
function that defines a P4 program (e.g. "tests.e2e.examples.basic_forward.basic_forward").
"""

from __future__ import annotations

import importlib
import sys

from p4py.compiler import compile
from p4py.sim import simulate
from tests.infra.stf_runner import match_hex, stf_to_sim_inputs


def run_stf_sim_test(module_path: str, stf_path: str) -> bool:
    """Compile a P4Py program and run an STF test through the simulator."""
    mod = importlib.import_module(module_path)
    program = compile(mod.main)

    with open(stf_path) as f:
        stf_text = f.read()
    sim_inputs = stf_to_sim_inputs(stf_text)

    passed = True
    expect_idx = 0
    for pkt in sim_inputs.packets:
        result = simulate(
            program,
            packet=pkt.data,
            ingress_port=pkt.port,
            table_entries=sim_inputs.table_entries,
        )
        if expect_idx >= len(sim_inputs.expects):
            continue

        expect = sim_inputs.expects[expect_idx]
        expect_idx += 1

        if expect.pattern is None:
            continue

        if result.dropped:
            print(f"FAIL: expected packet on port {expect.port}, got drop")
            passed = False
            continue

        if result.egress_port != expect.port:
            print(
                f"FAIL: expected port {expect.port}, got {result.egress_port}"
            )
            passed = False
            continue

        actual_hex = result.packet.hex()
        if not match_hex(actual_hex, expect.pattern):
            print(f"FAIL: packet mismatch on port {expect.port}")
            print(f"  expected: {expect.pattern}")
            print(f"  actual:   {actual_hex}")
            passed = False

    if passed:
        print("PASS: all expected packets matched")
    return passed


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <module_path> <stf_file>", file=sys.stderr)
        sys.exit(2)
    if not run_stf_sim_test(sys.argv[1], sys.argv[2]):
        sys.exit(1)


if __name__ == "__main__":
    main()
