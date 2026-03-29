# eBPF Model Coverage

What [ebpf_model][ebpf_model.p4] constructs P4Py currently supports, based on
the [ebpf_model.p4][ebpf_model.p4] header and the [p4c eBPF backend][p4c-ebpf]
documentation.

[ebpf_model.p4]: https://github.com/p4lang/p4c/blob/main/p4include/ebpf_model.p4
[p4c-ebpf]: https://github.com/p4lang/p4c/tree/main/backends/ebpf

## Pipeline blocks

| Block  | Supported | Notes                                    |
| ------ | --------- | ---------------------------------------- |
| Parser | Yes       |                                          |
| Filter | Yes       | `bool pass_` output controls accept/drop |

## Table implementation

| Property      | Supported | Notes |
| ------------- | --------- | ----- |
| `hash_table`  | Yes       |       |
| `array_table` | Yes       |       |

## Metadata

The eBPF filter architecture has no standard metadata type. Header types are
inferred from the parser's type annotations.

## Externs

No eBPF externs are currently supported.

## Packet operations

| Operation | Supported | Notes                            |
| --------- | --------- | -------------------------------- |
| Accept    | Yes       | `pass_ = True` in filter control |
| Drop      | Yes       | `pass_ = False` or parser reject |

## See also

- [P4 spec coverage](p4-spec-coverage.md) for language-level constructs.
- [v1model coverage](v1model-coverage.md) for v1model-specific constructs.
