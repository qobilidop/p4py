# v1model coverage

What [v1model][v1model.p4] constructs P4Py currently supports, based on the
[v1model.p4][v1model.p4] header and the [simple_switch][simple_switch]
behavioral model documentation.

[v1model.p4]: https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4
[simple_switch]: https://github.com/p4lang/behavioral-model/blob/main/docs/simple_switch.md

## Pipeline blocks

| Block           | Supported | Notes                 |
| --------------- | --------- | --------------------- |
| Parser          | Yes       |                       |
| VerifyChecksum  | Yes       | Empty stub if omitted |
| Ingress         | Yes       |                       |
| Egress          | Yes       | Empty stub if omitted |
| ComputeChecksum | Yes       | Empty stub if omitted |
| Deparser        | Yes       |                       |

## `standard_metadata_t`

| Field                      | Supported | Notes                    |
| -------------------------- | --------- | ------------------------ |
| `ingress_port`             | Yes       | Read-only                |
| `egress_spec`              | Yes       | Write to set output port |
| `egress_port`              | No        |                          |
| `instance_type`            | No        |                          |
| `packet_length`            | No        |                          |
| `enq_timestamp`            | No        |                          |
| `enq_qdepth`               | No        |                          |
| `deq_timedelta`            | No        |                          |
| `deq_qdepth`               | No        |                          |
| `ingress_global_timestamp` | No        |                          |
| `egress_global_timestamp`  | No        |                          |
| `mcast_grp`                | No        |                          |
| `egress_rid`               | No        |                          |
| `checksum_error`           | No        |                          |
| `parser_error`             | No        |                          |
| `priority`                 | No        |                          |

## Externs

| Extern                         | Supported | Notes                         |
| ------------------------------ | --------- | ----------------------------- |
| `mark_to_drop`                 | Yes       | Sets egress_spec to drop port |
| `counter`                      | No        |                               |
| `direct_counter`               | No        |                               |
| `meter`                        | No        |                               |
| `direct_meter`                 | No        |                               |
| `register`                     | No        |                               |
| `action_profile`               | No        |                               |
| `action_selector`              | No        |                               |
| `hash`                         | No        |                               |
| `digest`                       | No        |                               |
| `random`                       | No        |                               |
| `verify_checksum`              | Yes       | No-op in simulation           |
| `update_checksum`              | Yes       | RFC 1071 ones' complement     |
| `verify_checksum_with_payload` | No        |                               |
| `update_checksum_with_payload` | No        |                               |
| `log_msg`                      | No        |                               |
| `assert`                       | No        |                               |
| `assume`                       | No        |                               |
| `truncate`                     | No        |                               |

## Packet operations

| Operation               | Supported | Notes |
| ----------------------- | --------- | ----- |
| Unicast (`egress_spec`) | Yes       |       |
| Drop (`mark_to_drop`)   | Yes       |       |
| Multicast (`mcast_grp`) | No        |       |
| Clone                   | No        |       |
| Resubmit                | No        |       |
| Recirculate             | No        |       |

## See also

- [P4 spec coverage](p4-spec-coverage.md) for language-level constructs.
