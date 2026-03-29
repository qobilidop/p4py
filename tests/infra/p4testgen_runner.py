"""Run a p4testgen test for a P4Py program.

CLI usage: python p4testgen_runner.py <module_path> <p4testgen_binary>

Compiles the P4Py program, emits P4-16 source, runs p4testgen to generate
STF tests, then verifies the simulator produces the expected output for each.
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
import tempfile

from p4py.backend.p4 import emit
from p4py.compiler import compile
from p4py.ir.nodes import EbpfProgram
from p4py.sim import simulate
from tests.infra.stf_runner import match_hex, stf_to_sim_inputs


def _p4c_root(p4testgen_path: str) -> str:
    """Derive the p4c root from the p4testgen binary path.

    The binary is at {runfiles}/p4c+/backends/p4tools/p4testgen.
    """
    return os.path.dirname(os.path.dirname(os.path.dirname(p4testgen_path)))


def _run_p4testgen(
    p4testgen_path: str,
    p4_path: str,
    out_dir: str,
    target: str = "bmv2",
    arch: str = "v1model",
) -> list[str]:
    """Run p4testgen on a P4 file. Returns paths to generated STF files."""
    root = _p4c_root(p4testgen_path)
    p4include = os.path.join(root, "p4include")
    cmd = [
        p4testgen_path,
        "-I",
        p4include,
    ]
    if target == "ebpf":
        # eBPF model includes are in a separate directory.
        ebpf_include = os.path.join(root, "backends", "ebpf", "p4include")
        cmd.extend(["-I", ebpf_include])
    cmd.extend(
        [
            "--target",
            target,
            "--arch",
            arch,
            "--test-backend",
            "stf",
            "--max-tests",
            "0",
            "--out-dir",
            out_dir,
            p4_path,
        ]
    )
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"p4testgen failed:\n{result.stderr}")
    return sorted(
        os.path.join(out_dir, f) for f in os.listdir(out_dir) if f.endswith(".stf")
    )


def run_p4testgen_test(module_path: str, p4testgen_path: str) -> bool:
    """Compile a P4Py program and run p4testgen-generated tests."""
    mod = importlib.import_module(module_path)
    program = compile(mod.main)
    p4_source = emit(program)

    # Detect target/arch from program type.
    if isinstance(program, EbpfProgram):
        target, arch = "ebpf", "ebpf"
    else:
        target, arch = "bmv2", "v1model"

    passed = True
    with tempfile.TemporaryDirectory() as tmpdir:
        p4_path = os.path.join(tmpdir, "program.p4")
        with open(p4_path, "w") as f:
            f.write(p4_source)

        testgen_dir = os.path.join(tmpdir, "testgen")
        os.makedirs(testgen_dir)
        stf_files = _run_p4testgen(
            p4testgen_path, p4_path, testgen_dir, target=target, arch=arch
        )
        if not stf_files:
            print("FAIL: p4testgen produced no tests")
            return False

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
                if len(sim_results) != len(sim_inputs.expects):
                    print(f"FAIL {test_name}: result/expect count mismatch")
                    passed = False
                    continue
                for (egress_port, pkt_hex), expect in zip(
                    sim_results, sim_inputs.expects
                ):
                    if expect.pattern is not None:
                        if egress_port != expect.port:
                            print(
                                f"FAIL {test_name}: expected port"
                                f" {expect.port}, got {egress_port}"
                            )
                            passed = False
                        elif pkt_hex is None:
                            print(f"FAIL {test_name}: packet was dropped")
                            passed = False
                        elif not match_hex(pkt_hex, expect.pattern):
                            print(f"FAIL {test_name}: packet mismatch")
                            print(f"  expected: {expect.pattern}")
                            print(f"  actual:   {pkt_hex}")
                            passed = False
            else:
                for egress_port, _pkt_hex in sim_results:
                    if egress_port != -1:
                        print(
                            f"FAIL {test_name}: expected drop, got port {egress_port}"
                        )
                        passed = False

    if passed:
        print(f"PASS: all {len(stf_files)} p4testgen tests matched")
    return passed


def main() -> None:
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <module_path> <p4testgen_binary>",
            file=sys.stderr,
        )
        sys.exit(2)
    if not run_p4testgen_test(sys.argv[1], sys.argv[2]):
        sys.exit(1)


if __name__ == "__main__":
    main()
