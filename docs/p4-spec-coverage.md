# P4 spec coverage

What [P4-16 language spec][spec] constructs P4Py currently supports.

P4Py targets **v1model** on a minimal profile (P4Mini). The tables below map
supported constructs to their spec sections.

[spec]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html

## Types

| Construct     | Supported | Spec section                | Notes                            |
| ------------- | --------- | --------------------------- | -------------------------------- |
| `bit<W>`      | Yes       | [§7.1 Base types][bit]      | Only numeric type                |
| `int<W>`      | No        | [§7.1 Base types][bit]      |                                  |
| `varbit`      | No        | [§7.1 Base types][bit]      |                                  |
| `bool`        | No        | [§7.1 Base types][bit]      |                                  |
| `header`      | Yes       | [§7.2 Header types][header] | Flat only, all fields `bit<W>`   |
| Header stacks | No        | [§7.2 Header types][header] |                                  |
| `struct`      | Yes       | [§7.2 Header types][struct] | Members must be header instances |
| `enum`        | No        | [§7.3 Other types][bit]     |                                  |
| `typedef`     | No        | [§7.3 Other types][bit]     |                                  |

[bit]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-bit-ops
[header]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-header-types
[struct]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-struct-types

## Parser

| Construct                | Supported | Spec section                            | Notes                                  |
| ------------------------ | --------- | --------------------------------------- | -------------------------------------- |
| Parser declaration       | Yes       | [§13.1 Parser declaration][parser-decl] |                                        |
| Named states             | Yes       | [§13.3 Parser states][parser-state]     | First state is implicit start          |
| `extract()`              | Yes       | [§13.4 Data extraction][extract]        |                                        |
| Unconditional transition | Yes       | [§13.6 Transition][transition]          |                                        |
| `transition select`      | Yes       | [§13.6 Select][select]                  | Single field, integer or default cases |
| `lookahead`              | No        | [§13.4 Data extraction][extract]        |                                        |
| Sub-parsers              | No        | [§13.1 Parser declaration][parser-decl] |                                        |
| Value sets               | No        | [§13.6 Select][select]                  |                                        |

[parser-decl]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-parser-decl
[parser-state]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-parser-state-stmt
[extract]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-packet-data-extraction
[transition]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-transition
[select]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-select

## Expressions

| Construct                     | Supported | Spec section            | Notes                        |
| ----------------------------- | --------- | ----------------------- | ---------------------------- |
| Integer literals              | Yes       | [§8 Expressions][exprs] | Decimal and hex              |
| Field access                  | Yes       | [§8 Expressions][exprs] | `hdr.ipv4.dstAddr`           |
| `+`, `-`                      | Yes       | [§8 Expressions][exprs] |                              |
| Bitwise (`&`, `\|`, `^`, `~`) | No        | [§8 Expressions][exprs] |                              |
| Shifts (`<<`, `>>`)           | No        | [§8 Expressions][exprs] |                              |
| Comparison (`==`, `!=`)       | No        | [§8 Expressions][exprs] | Only in `transition select`  |
| Slicing                       | No        | [§8 Expressions][exprs] |                              |
| Concatenation (`++`)          | No        | [§8 Expressions][exprs] |                              |
| Casts                         | No        | [§8 Expressions][exprs] |                              |
| `.isValid()`                  | Yes       | [§8 Expressions][exprs] | In control apply blocks only |
| `.setValid()`                 | No        | [§8 Expressions][exprs] |                              |
| `.setInvalid()`               | No        | [§8 Expressions][exprs] |                              |

[exprs]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-exprs

## Statements

| Construct        | Supported | Spec section            | Notes                          |
| ---------------- | --------- | ----------------------- | ------------------------------ |
| Assignment       | Yes       | [§12 Statements][stmts] |                                |
| Method call      | Yes       | [§12 Statements][stmts] | `extract`, `emit`              |
| Function call    | Yes       | [§12 Statements][stmts] | `mark_to_drop`                 |
| `if`/`else`      | Yes       | [§12 Statements][stmts] | Condition must be `.isValid()` |
| `switch`         | No        | [§12 Statements][stmts] |                                |
| Block statements | No        | [§12 Statements][stmts] |                                |

[stmts]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-stmts

## Control blocks

| Construct           | Supported | Spec section                  | Notes                          |
| ------------------- | --------- | ----------------------------- | ------------------------------ |
| Control declaration | Yes       | [§14 Control blocks][control] |                                |
| Actions             | Yes       | [§14 Control blocks][actions] | Direction-less parameters only |
| Tables              | Yes       | [§14 Control blocks][tables]  |                                |
| `exact` match       | Yes       | [§14 Control blocks][tables]  |                                |
| `lpm` match         | Yes       | [§14 Control blocks][tables]  |                                |
| `ternary` match     | No        | [§14 Control blocks][tables]  |                                |
| `range` match       | No        | [§14 Control blocks][tables]  |                                |
| `table.apply()`     | Yes       | [§14 Control blocks][control] |                                |
| `const entries`     | No        | [§14 Control blocks][tables]  |                                |

[control]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-control
[actions]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-actions
[tables]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-tables

## Deparsing

| Construct            | Supported | Spec section             | Notes |
| -------------------- | --------- | ------------------------ | ----- |
| Deparser declaration | Yes       | [§16 Deparsing][deparse] |       |
| `emit()`             | Yes       | [§16 Deparsing][deparse] |       |

[deparse]: https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-deparse

## See also

- [v1model coverage](v1model-coverage.md) for architecture-specific constructs.
