# Architecture

P4Py uses a hub-and-spoke architecture centered on a P4 AST. Python source flows
in through the decorator API, gets transformed into AST nodes, and flows out
through backends (simulator, P4 emitter). All components communicate through the
AST — they never depend on each other directly.

## Data flow

```text
Python source
    → [Decorator API] → AST parsing + validation
    → [P4 AST] (canonical representation)
    → [Simulator]  → packet output
    → [P4 Emitter] → .p4 source → p4c → BMv2
```

## Why AST parsing

P4 is a static language with compile-time-determined control flow. AST parsing
(inspecting decorated functions via Python's `ast` module) captures the full
program structure — including all branches of `transition select` — in one pass.
The alternative, tracing (executing with proxy objects), would only see one
execution path per run, making it unsuited for capturing parser state machines.

The restriction on Python features inside decorated functions is a feature, not
a bug — it ensures user code maps cleanly to P4 constructs.

## Components

### P4 AST (the hub)

In-memory representation of P4 programs as Python data structures. Node types
correspond to P4 constructs: headers, parsers, tables, actions, controls, and
programs. All validation and transformation operates on this representation.
Language profiles constrain which node types and features are valid.

### Decorator API (Python to AST)

The entry point for users. Decorators like `@p4py.parser`, `@p4py.control`,
`@p4py.action`, and `@p4py.table` inspect the decorated function's Python AST
via the `ast` module and build P4 AST nodes. Data types like `p4py.Header`,
`p4py.Struct`, and `p4py.bit(W)` define the type system. The API validates that
the Python code uses only the supported subset.

### Simulator (AST to execution)

Interprets P4 AST nodes in Python: packet-in, packet-out. The parser runs as a
state machine over a byte buffer. Tables are Python dicts (exact match) with
installed entries. Useful for rapid prototyping and testing without external
tools.

### P4 emitter (AST to `.p4`)

Traverses the AST and emits syntactically valid P4-16 source targeting v1model.
Generates boilerplate such as includes and empty pass-through blocks for unused
v1model stages. Output can be compiled by `p4c` and run on BMv2.

### Externs (`@p4py.extern`)

Python-defined P4 externs with an extern registry. The simulator calls the
Python implementation directly. The P4 emitter generates `extern` declarations.
Scoped to future work.
