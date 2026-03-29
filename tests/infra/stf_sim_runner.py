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
    sim_results: list[tuple[int, str | None]] = []
    for pkt in sim_inputs.packets:
        result = simulate(
            program,
            packet=pkt.data,
            ingress_port=pkt.port,
            table_entries=sim_inputs.table_entries,
            clone_session_map=sim_inputs.clone_session_map,
        )
        # Clone outputs first, then the original.
        for clone_port, clone_pkt in result.clone_outputs:
            sim_results.append((clone_port, clone_pkt.hex()))
        if result.dropped:
            sim_results.append((-1, None))
        else:
            sim_results.append((result.egress_port, result.packet.hex()))

    if len(sim_results) != len(sim_inputs.expects):
        print(
            f"FAIL: result/expect count mismatch"
            f" ({len(sim_results)} vs {len(sim_inputs.expects)})"
        )
        return False

    for (egress_port, pkt_hex), expect in zip(sim_results, sim_inputs.expects):
        if expect.pattern is not None:
            if egress_port != expect.port:
                print(f"FAIL: expected port {expect.port}, got {egress_port}")
                passed = False
            elif pkt_hex is None:
                print(f"FAIL: expected packet on port {expect.port}, got drop")
                passed = False
            elif not match_hex(pkt_hex, expect.pattern):
                print(f"FAIL: packet mismatch on port {expect.port}")
                print(f"  expected: {expect.pattern}")
                print(f"  actual:   {pkt_hex}")
                passed = False
        elif expect.pattern is None and egress_port != expect.port:
            # Expect line with no pattern — just check port.
            if egress_port == -1:
                continue  # Dropped packet matches any portless expect.
            if egress_port != expect.port:
                print(f"FAIL: expected port {expect.port}, got {egress_port}")
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
