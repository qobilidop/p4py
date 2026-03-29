"""eBPF filter architecture for P4Py.

Defines the ebpfFilter pipeline: a parser and a filter control.
Matches the ebpf_model.p4 architecture definition.
"""

from dataclasses import dataclass

import p4py.lang as p4
from p4py.arch.base import Architecture, BlockSpec
from p4py.lang import _Spec


class _TableImpl:
    """An eBPF table implementation extern (hash_table or array_table)."""

    def __init__(self, name: str, size: int) -> None:
        self._p4_kind = "table_impl"
        self._p4_name = name
        self._p4_size = size

    def __repr__(self) -> str:
        return f"{self._p4_name}({self._p4_size})"


def hash_table(size: int) -> _TableImpl:
    """Create a hash_table implementation property."""
    return _TableImpl("hash_table", size)


def array_table(size: int) -> _TableImpl:
    """Create an array_table implementation property."""
    return _TableImpl("array_table", size)


class EbpfFilterArch(Architecture):
    @property
    def include(self) -> str:
        return "ebpf_model.p4"

    @property
    def pipeline(self) -> tuple[BlockSpec, ...]:
        return (
            BlockSpec("parser", "parser"),
            BlockSpec("filter", "control"),
        )

    def block_signature(self, block_name, struct_names, param_names=()):
        ht = struct_names["headers"]
        if block_name == "parser":
            pkt, h = param_names if len(param_names) == 2 else ("p", "headers")
            return f"parser {{name}}(packet_in {pkt}, out {ht} {h})"
        # filter: control(inout headers, out bool pass_)
        h, out = param_names if len(param_names) == 2 else ("headers", "pass_")
        return f"control {{name}}(inout {ht} {h}, out bool {out})"

    def main_instantiation(self, block_names):
        return f"ebpfFilter({block_names['parser']}(), {block_names['filter']}()) main;"

    def emit_boilerplate(self, lines, spec, struct_names):
        pass  # All blocks required; no boilerplate needed.

    def process_packet(
        self, package, engine_cls, packet, ingress_port, table_entries,
        clone_session_map=None,
    ):
        from p4py.sim import SimResult

        eng = engine_cls(package, packet, table_entries)

        parser = _get_block(package, "parser")
        terminal = eng.run_parser(parser)
        if terminal == "reject":
            return SimResult(packet=None, egress_port=-1, dropped=True)

        # eBPF: if no headers were successfully extracted, drop.
        any_valid = any(h.valid for h in eng.state.headers.values())
        if not any_valid:
            return SimResult(packet=None, egress_port=-1, dropped=True)

        # Run filter control.
        filt = _get_block(package, "filter")
        eng.run_control(filt)

        # Check if any control local is truthy (the accept/pass output).
        accepted = any(v for v in eng.state.control_locals.values())
        if accepted:
            return SimResult(packet=bytes(packet), egress_port=0, dropped=False)
        return SimResult(packet=None, egress_port=-1, dropped=True)


def _get_block(package, name):
    """Look up a block by name in a Package."""
    for entry in package.blocks:
        if entry.name == name:
            return entry.decl
    return None


_EBPF_ARCH = EbpfFilterArch()


@dataclass
class ebpfFilter:  # noqa: N801
    """eBPF filter pipeline with field order matching ebpf_model.p4.

    Header types are inferred from the parser's type annotations
    (``headers`` parameter).
    """

    parser: _Spec | None = None
    filter: _Spec | None = None

    def __post_init__(self) -> None:
        self.arch: Architecture = _EBPF_ARCH
        if self.parser is not None:
            ann_values = list(self.parser._p4_annotations.values())
            self.headers: type[p4.struct] = ann_values[0] if ann_values else None
