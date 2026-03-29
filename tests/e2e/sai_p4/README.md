# SAI P4 tests

End-to-end tests translating programs from the
[sonic-net/sonic-pins](https://github.com/sonic-net/sonic-pins) `sai_p4/` corpus
into P4Py.

## Background

The `sai_p4` corpus is a production-grade, SAI-compatible P4 program for
Google's data center switches running on SONiC. It uses a "fixed +
instantiations" architecture:

- `fixed/` — Shared P4 modules (headers, parser, routing, ACL, mirroring, etc.)
- `instantiations/google/` — Top-level programs that compose fixed modules with
  deployment-specific configuration

There are four instantiations, from simplest to most complex:

| Instantiation             | Description                                             |
| ------------------------- | ------------------------------------------------------- |
| `wbb.p4`                  | WAN Building Block — trivial pipeline, single ACL table |
| `tor.p4`                  | Top-of-rack — full routing, ACL, mirroring, VLAN        |
| `middleblock.p4`          | Spine switch — similar to ToR                           |
| `fabric_border_router.p4` | Border router — all features enabled                    |

## Approach

We mirror the upstream directory structure, writing `.py` files alongside (or in
place of) the original `.p4` files:

```
tests/e2e/sai_p4/
  fixed/
    headers.py
    metadata.py
    ...
  instantiations/google/
    wbb.py
    acl_wbb_ingress.py
    ...
```

Each top-level instantiation (e.g., `wbb.py`) imports from `fixed/` modules and
assembles a V1Switch pipeline, just as the `.p4` files use `#include`. The P4Py
compiler produces a single combined `.p4` output from the scattered `.py` files.

## Current target

**`wbb.p4`** — the simplest instantiation. Effective pipeline:

- Parser: trivial (start → accept)
- Ingress: single `acl_wbb_ingress_table` (optional + ternary match, direct
  meter, direct counter, clone actions)
- Egress, checksum, deparser: empty

Despite the trivial pipeline, a faithful translation exercises the full data
model (`headers_t` with ~20 headers, `local_metadata_t` with ~50 fields) and
drives new P4Py features: `optional` match kind, direct counters/meters, clone
extern, typedef/type, enum, and const declarations.

## Deferred

- **Annotations** (`@id`, `@sai_action`, `@entry_restriction`, etc.) — needs its
  own design; will be added later.
- **Conditional compilation** — not needed while targeting a single
  instantiation. When we add a second target, we'll design a solution using
  Python-native conditionals.
