"""Testgen test: verify P4Py simulator against p4testgen predictions.

Compiles the P4Py program to P4-16, runs p4testgen to auto-generate STF
tests covering all program paths, then verifies the Python simulator
produces the expected output for each test.
"""

import os
import subprocess
import tempfile

from p4py.backend.p4 import emit
from p4py.compiler import compile
from p4py.sim import simulate
from tests.e2e.examples.basic_forward.basic_forward import main
from tests.infra.stf_runner import match_hex, stf_to_sim_inputs

_P4TESTGEN = os.path.join(
    os.environ.get("TEST_SRCDIR", ""),
    os.environ.get("TEST_WORKSPACE", "_main"),
    "external/p4c+/backends/p4tools/p4testgen",
)


def _run_p4testgen(p4_path: str, out_dir: str) -> list[str]:
    """Run p4testgen on a P4 file. Returns paths to generated STF files."""
    result = subprocess.run(
        [
            _P4TESTGEN,
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
    def test_simulator_matches_p4testgen(self):
        """P4Py simulator matches p4testgen predictions on all paths."""
        program = compile(main)
        p4_source = emit(program)

        with tempfile.TemporaryDirectory() as tmpdir:
            p4_path = os.path.join(tmpdir, "basic_forward.p4")
            with open(p4_path, "w") as f:
                f.write(p4_source)

            testgen_dir = os.path.join(tmpdir, "testgen")
            os.makedirs(testgen_dir)
            stf_files = _run_p4testgen(p4_path, testgen_dir)
            assert stf_files, "p4testgen produced no tests"

            for stf_path in stf_files:
                test_name = os.path.basename(stf_path)
                with open(stf_path) as f:
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
                        sim_results.append((result.egress_port, result.packet.hex()))

                if sim_inputs.expects:
                    assert len(sim_results) == len(sim_inputs.expects), (
                        f"{test_name}: result/expect count mismatch"
                    )
                    for (egress_port, pkt_hex), expect in zip(
                        sim_results, sim_inputs.expects
                    ):
                        if expect.pattern is not None:
                            assert egress_port == expect.port, (
                                f"{test_name}: expected port"
                                f" {expect.port}, got {egress_port}"
                            )
                            assert pkt_hex is not None, (
                                f"{test_name}: packet was dropped"
                            )
                            assert match_hex(pkt_hex, expect.pattern), (
                                f"{test_name}: packet mismatch\n"
                                f"  expected: {expect.pattern}\n"
                                f"  actual:   {pkt_hex}"
                            )
                else:
                    for egress_port, pkt_hex in sim_results:
                        assert egress_port == -1, (
                            f"{test_name}: expected drop, got port {egress_port}"
                        )
