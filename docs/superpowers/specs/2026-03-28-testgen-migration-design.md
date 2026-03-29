# Test infrastructure migration: BMv2 to p4testgen

## Goal

Replace BMv2-based testing with p4testgen-only testing. This removes the BMv2
dependency (and its sudo/veth/Thrift requirements), simplifies the test
infrastructure, and enables hermetic Bazel-sandboxed tests.

## Test types

Three test types going forward:

| Type | File pattern | What it tests | External tools |
|------|-------------|---------------|----------------|
| Golden | `*_golden_test.py` | Emitter output matches committed `.p4` | None |
| STF | `*_stf_test.py` | Simulator vs hand-written STF | None |
| Testgen | `*_testgen_test.py` | Simulator vs p4testgen-generated STF | `p4testgen` |

### Golden tests (unchanged)

Compile P4Py program, emit P4-16, assert it matches the committed `.p4` file.
Pure Python, no external tools.

### STF tests (new, replaces diff tests)

Run hand-written STF test vectors through the P4Py simulator only. The flow:

1. Compile P4Py program to IR.
2. Parse `.stf` file via `stf_to_sim_inputs()`.
3. For each packet: `simulate()` and assert output matches STF `expect` lines.

No BMv2 comparison. These tests validate the simulator against curated test
vectors.

### Testgen tests (simplified)

Use p4testgen to auto-generate STF test cases, then run them through the
simulator. The flow:

1. Compile P4Py program to IR, emit P4-16 source to a temp file.
2. Run `p4testgen` on the P4 file to generate STF files.
3. For each generated STF: parse via `stf_to_sim_inputs()`, simulate, assert.

p4testgen is obtained from `@p4c//backends/p4tools:p4testgen` (Bazel-built).

## What gets removed

### Files to delete

- `tests/e2e/examples/basic_forward/basic_forward_diff_test.py`
- `tests/e2e/p4_16_samples/basic_routing_bmv2/basic_routing_bmv2_diff_test.py`
- `tests/e2e/p4_16_samples/basic_routing_bmv2/basic_routing_bmv2_sim_test.py`

### Code to remove from `tests/infra/stf_runner.py`

All BMv2-related code (~300 lines):

- `compile_p4()` — calls `p4c-bm2-ss`
- `parse_stf_add()` / `parse_stf_setdefault()` — BMv2 CLI command translation
- `_setup_veth_pair()` / `_teardown_veth_pair()` — virtual ethernet management
- `write_pcap()` / `read_pcap()` — pcap file I/O
- `_wait_for_thrift()` — Thrift server polling
- `run_stf_test()` — full BMv2 test orchestrator

### Code to keep in `tests/infra/stf_runner.py`

- `parse_stf_string()` / `parse_stf()` — STF parsing
- `stf_to_sim_inputs()` — STF-to-simulator translation
- `match_hex()` — hex pattern matching with wildcards
- Supporting types: `SimInputs`, `SimPacket`, `SimExpect`

### Bazel changes

- `tests/infra/stf_test.bzl` — rewrite to run STF tests without BMv2
  (pure Python simulator test, no `local = True`)
- Remove `local = True` and `tags = ["local"]` from test targets where BMv2 is
  no longer needed
- Testgen tests need `@p4c//backends/p4tools:p4testgen` as a `data` dependency

### Test infrastructure tests

- `tests/infra/stf_runner_test.py` — remove tests for deleted functions
  (`TestParseStfAdd`, `TestParseStfSetdefault`), keep tests for remaining
  functions

## p4testgen Bazel integration

The testgen tests need access to the `p4testgen` binary. Two options:

1. **data dependency** — add `@p4c//backends/p4tools:p4testgen` as `data` in
   the `py_test` target, locate it via `runfiles` at test time.
2. **Build and use `bazel-bin` path** — simpler but less hermetic.

Option 1 is preferred. The test code resolves the binary path from runfiles
rather than assuming it's on `$PATH`.

## Migration order

1. Remove BMv2 code from `stf_runner.py` and its tests.
2. Delete diff tests and sim tests.
3. Create STF tests (rename/rewrite from diff tests, simulator-only).
4. Update testgen tests to use Bazel-built p4testgen (no BMv2 path).
5. Update BUILD files and `stf_test.bzl`.
6. Update `tests/e2e/README.md`.
