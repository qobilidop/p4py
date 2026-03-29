# Architecture

P4Py uses a layered architecture centered on a frozen-dataclass IR. Python
source flows in through the decorator API, gets compiled into IR nodes, and
flows out through backends (P4 emitter, simulator). All components communicate
through the IR - they never depend on each other directly. Architecture-specific
behavior (v1model, eBPF) is handled by pluggable architecture descriptors.

## Data flow

```text
Python source (DSL)
    → [Compiler] → Package IR (arch-agnostic)
    → [Emitter]  → .p4 source → p4c
    → [Simulator] → SimEngine + arch.process_packet() → packet output
```

## Why AST parsing

P4 is a static language with compile-time-determined control flow. AST parsing
(inspecting decorated functions via Python's `ast` module) captures the full
program structure - including all branches of `transition select` - in one pass.
The alternative, tracing (executing with proxy objects), would only see one
execution path per run, making it unsuited for capturing parser state machines.

The restriction on Python features inside decorated functions is a feature, not
a bug - it ensures user code maps cleanly to P4 constructs.

## Components

### `lang.py` - DSL surface

The entry point for users. Provides decorators (`@p4.parser`, `@p4.control`,
`@p4.deparser`), sentinels (`@p4.action`, `p4.table`), type constructors
(`p4.bit(W)`, `p4.bool`, `p4.header`, `p4.struct`), match kinds (`p4.exact`,
`p4.lpm`), literal helpers (`p4.literal()`, `p4.hex()`), built-in actions
(`p4.NoAction`), and parser terminals (`p4.ACCEPT`, `p4.REJECT`).

### `ir.py` - Intermediate representation (the hub)

Frozen dataclasses representing P4 programs. Node types correspond to P4
constructs: types (`BitType`, `BoolType`, `HeaderType`, `StructType`),
expressions (`FieldAccess`, `IntLiteral`, `BoolLiteral`, `ArithOp`, `IsValid`,
`ListExpression`), statements (`Assignment`, `MethodCall`, `FunctionCall`,
`TableApply`, `IfElse`, `SwitchAction`), declarations (`ParserDecl`,
`ControlDecl`, `DeparserDecl`, `ActionDecl`, `TableDecl`), and the top-level
`Package` type that bundles headers, structs, blocks, and an architecture
reference.

### `compiler.py` - AST to IR compilation

Parses Python AST from captured function sources and produces an IR `Package`.
Architecture-agnostic: iterates over the architecture's pipeline spec and
compiles each user-provided block. Handles parser states, transitions, `select`,
actions, tables (including `const_entries` and `implementation`), and deparser
emit order.

### `emitter/p4.py` - IR to P4-16 text

Traverses IR nodes and emits syntactically valid P4-16 source.
Architecture-specific details (block signatures, boilerplate for omitted blocks,
`#include`, `main` instantiation) are delegated to the architecture descriptor
on the `Package`. The emitter itself is fully arch-agnostic.

### `sim/engine.py` - Shared simulation engine

Provides execution primitives for parsing, control, and deparsing. The
`SimEngine` class manages packet state, header instances, metadata, and an
extern registry. Architectures register their externs (e.g., `mark_to_drop`,
`verify_checksum`) via `engine.register_extern()`. The engine handles extract,
table lookup (exact and LPM with `const_entries`), action execution, and
deparsing.

### `sim/__init__.py` - Simulator entry point

Thin `simulate()` wrapper that creates a `SimEngine` and delegates to
`arch.process_packet()`. Returns a `SimResult` with the output packet, egress
port, and drop status.

### `arch/base.py` - Architecture ABC

Defines the `Architecture` abstract base class and `BlockSpec` dataclass. Each
architecture implements: `include` (header file), `pipeline` (ordered block
specs), `block_signature()`, `main_instantiation()`, `emit_boilerplate()`, and
`process_packet()`.

### `arch/v1model.py` - v1model architecture

Implements the V1Switch pipeline: parser, verify_checksum, ingress, egress,
compute_checksum, deparser. Defines `standard_metadata_t`, externs
(`mark_to_drop`, `verify_checksum`, `update_checksum`), and
`HashAlgorithm.csum16`. Optional blocks emit empty stubs when omitted.

### `arch/ebpf_model.py` - eBPF architecture

Implements the ebpfFilter pipeline: parser and filter control. The filter
control has a `bool pass_` output parameter. Provides table implementation
properties (`hash_table`, `array_table`). No standard metadata or externs.

## See also

- [P4 spec coverage](p4-spec-coverage.md) for supported language constructs.
- [v1model coverage](v1model-coverage.md) for v1model-specific constructs.
- [eBPF model coverage](ebpf-model-coverage.md) for eBPF-specific constructs.
