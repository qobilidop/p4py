"""Diff test: P4Py simulator vs BMv2 for basic_forward.

Compiles the P4Py program to P4-16, runs the same STF test against both
the Python simulator and BMv2 simple_switch, and asserts matching output.
"""

import os
import tempfile

from e2e_tests.basic_forward.basic_forward import main
from e2e_tests.stf_runner import (
    match_hex,
    run_stf_test,
    stf_to_sim_inputs,
)
from p4py.backend.p4 import emit
from p4py.compiler import compile
from p4py.sim import simulate

_HERE = os.path.dirname(__file__)
_STF_PATH = os.path.join(_HERE, "basic_forward.stf")


class TestBasicForwardDiff:
    def test_simulator_matches_bmv2(self):
        """Both engines produce the same output for basic_forward.stf."""
        # Compile P4Py program to IR and emit P4-16 source.
        program = compile(main)
        p4_source = emit(program)

        # --- Simulator side ---
        with open(_STF_PATH) as f:
            stf_text = f.read()
        sim_inputs = stf_to_sim_inputs(stf_text)

        sim_results: list[tuple[int, str | None]] = []
        for pkt in sim_inputs.packets:
            result = simulate(
                program,
                packet=pkt.data,
                ingress_port=pkt.port,
                table_entries=sim_inputs.table_entries,
            )
            if result.dropped:
                sim_results.append((-1, None))
            else:
                sim_results.append(
                    (result.egress_port, result.packet.hex())
                )

        # Verify simulator against STF expectations.
        assert len(sim_results) == len(sim_inputs.expects)
        for (egress_port, pkt_hex), expect in zip(
            sim_results, sim_inputs.expects
        ):
            if expect.pattern is not None:
                assert egress_port == expect.port, (
                    f"Simulator: expected port {expect.port},"
                    f" got {egress_port}"
                )
                assert pkt_hex is not None, "Simulator: packet was dropped"
                assert match_hex(pkt_hex, expect.pattern), (
                    f"Simulator packet mismatch:\n"
                    f"  expected: {expect.pattern}\n"
                    f"  actual:   {pkt_hex}"
                )

        # --- BMv2 side ---
        with tempfile.TemporaryDirectory() as tmpdir:
            p4_path = os.path.join(tmpdir, "basic_forward.p4")
            with open(p4_path, "w") as f:
                f.write(p4_source)

            bmv2_passed = run_stf_test(p4_path, _STF_PATH)
            assert bmv2_passed, "BMv2 STF test failed"
