"""P4testgen diff test: P4Py simulator vs BMv2 for basic_forward.

Compiles the P4Py program to P4-16, runs p4testgen to auto-generate STF
tests covering all program paths, then runs each through both the Python
simulator and BMv2 and asserts matching behavior.
"""

import os
import subprocess
import tempfile

from p4py.backend.p4 import emit
from p4py.compiler import compile
from p4py.sim import simulate
from tests.e2e.basic_forward.basic_forward import main
from tests.infra.stf_runner import (
    match_hex,
    run_stf_test,
    stf_to_sim_inputs,
)


def _run_p4testgen(p4_path: str, out_dir: str) -> list[str]:
    """Run p4testgen on a P4 file. Returns paths to generated STF files."""
    result = subprocess.run(
        [
            "p4testgen",
            "--target",
            "bmv2",
            "--arch",
            "v1model",
            "--test-backend",
            "stf",
            "--max-tests",
            "0",
            "--out-dir",
            out_dir,
            p4_path,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"p4testgen failed:\n{result.stderr}")
    stf_files = sorted(
        os.path.join(out_dir, f) for f in os.listdir(out_dir) if f.endswith(".stf")
    )
    return stf_files


class TestBasicForwardTestgen:
    def test_simulator_matches_bmv2_on_generated_tests(self):
        """P4Py simulator and BMv2 agree on all p4testgen-generated tests."""
        program = compile(main)
        p4_source = emit(program)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Write emitted P4 source.
            p4_path = os.path.join(tmpdir, "basic_forward.p4")
            with open(p4_path, "w") as f:
                f.write(p4_source)

            # Generate STF tests.
            testgen_dir = os.path.join(tmpdir, "testgen")
            os.makedirs(testgen_dir)
            stf_files = _run_p4testgen(p4_path, testgen_dir)
            assert stf_files, "p4testgen produced no tests"

            for stf_path in stf_files:
                test_name = os.path.basename(stf_path)
                with open(stf_path) as f:
                    stf_text = f.read()
                sim_inputs = stf_to_sim_inputs(stf_text)

                # --- Simulator side ---
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
                        sim_results.append((result.egress_port, result.packet.hex()))

                # Verify simulator against STF expectations.
                if sim_inputs.expects:
                    assert len(sim_results) == len(sim_inputs.expects), (
                        f"{test_name}: result/expect count mismatch"
                    )
                    for (egress_port, pkt_hex), expect in zip(
                        sim_results, sim_inputs.expects
                    ):
                        if expect.pattern is not None:
                            assert egress_port == expect.port, (
                                f"{test_name}: Simulator expected port"
                                f" {expect.port}, got {egress_port}"
                            )
                            assert pkt_hex is not None, (
                                f"{test_name}: Simulator dropped packet"
                            )
                            assert match_hex(pkt_hex, expect.pattern), (
                                f"{test_name}: Simulator packet mismatch\n"
                                f"  expected: {expect.pattern}\n"
                                f"  actual:   {pkt_hex}"
                            )
                else:
                    # No expects means packet should be dropped.
                    for egress_port, pkt_hex in sim_results:
                        assert egress_port == -1, (
                            f"{test_name}: Simulator expected drop,"
                            f" got port {egress_port}"
                        )

                # --- BMv2 side ---
                bmv2_passed = run_stf_test(p4_path, stf_path)
                assert bmv2_passed, f"{test_name}: BMv2 STF test failed"
