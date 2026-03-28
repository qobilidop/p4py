# Roadmap

P4Py follows a two-milestone strategy. P4Mini proves the end-to-end architecture
works. P4Lite makes it useful for real-world P4 development.

## P4Mini (v0.1.0)

A minimal but complete end-to-end pipeline — Python source to AST to simulation
and P4 emission — targeting a strict subset of P4 on a minimal v1model profile.

### Deliverables

| Component | What it does |
|---|---|
| P4 AST | Core node types for the P4Mini language subset |
| Decorator API | `@p4py.parser`, `@p4py.control`, `@p4py.action`, `@p4py.table`, `p4py.Header`, `p4py.bit` |
| Simulator | Run P4Mini programs in Python, packet-in / packet-out |
| P4 emitter | Generate valid v1model `.p4` source from AST |

### Language scope

Details will be defined in a separate P4Mini spec. At a high level:

- `bit<W>` fixed-width types only
- DAG parser with `extract` and `transition select`
- `exact` match tables
- Basic assignment and `+`/`-` arithmetic
- Minimal v1model metadata (`ingress_port`, `egress_spec`)
- No externs, no stateful elements

### Testing strategy

- Unit tests for each component.
- Diff testing: Python simulator output vs BMv2 for the same emitted `.p4`.
- p4testgen for automated packet generation.

### Success criteria

Write an L2 switch in P4Py, simulate it, emit valid `.p4`, and diff-test against
BMv2.

## P4Lite (v1.0.0)

A useful P4 language subset with full v1model support.

### Scope (to be defined)

- Expanded language features (LPM/ternary match, header stacks, etc.)
- Full v1model pipeline and metadata.
- Python-defined externs via `@p4py.extern`.
- Capability profiles to validate against P4Mini or P4Lite.
