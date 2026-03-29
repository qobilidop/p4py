# End-to-end tests

End-to-end tests exercise the full P4Py pipeline: Python DSL to IR, compilation,
P4-16 emission, simulation, and p4testgen verification.

## Directory structure

- `examples/` — Tests for programs in the top-level `examples/` directory. Each
  subdirectory mirrors an example and contains its own copy of the P4Py program,
  the generated `.p4`, an `.stf` test scenario, and test files.

- `p4_16_samples/` — Tests adapted from the
  [p4lang/p4c](https://github.com/p4lang/p4c) test corpus
  (`testdata/p4_16_samples/`). Each subdirectory corresponds to a p4c test
  program, rewritten in P4Py. Programs may be simplified with `TODO` comments
  marking unsupported features to add later.

## Test types

- **Golden tests** (`*_golden_test.py`) — Verify the compiled P4-16 output
  matches a committed `.p4` file.
- **STF tests** (`*_stf_test.py`) — Run hand-written STF test vectors through
  the P4Py simulator and verify expected outputs.
- **Testgen tests** (`*_testgen_test.py`) — Use p4testgen to auto-generate test
  cases with expected outputs, then verify the P4Py simulator produces the
  expected results.
