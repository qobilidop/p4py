"""v1model architecture for P4Py.

Defines the minimal v1model subset: standard_metadata_t, mark_to_drop,
and V1Switch pipeline.
"""

from dataclasses import dataclass

import p4py.lang as p4
from p4py.arch.base import Architecture, BlockSpec
from p4py.lang import _Spec

_DROP_PORT = 511


def _get_block(package, name):
    """Look up a block declaration by name, returning None if absent."""
    for entry in package.blocks:
        if entry.name == name:
            return entry.decl
    return None


class standard_metadata_t(p4.header):
    ingress_port: p4.bit(9)
    egress_spec: p4.bit(9)


class _Extern:
    """A v1model extern function."""

    def __init__(self, name: str) -> None:
        self._p4_kind = "extern"
        self._p4_name = name

    def __repr__(self) -> str:
        return self._p4_name


mark_to_drop = _Extern("mark_to_drop")


class _HashAlgorithm:
    """v1model hash algorithm enum."""

    def __init__(self, name: str) -> None:
        self._p4_name = name

    def __repr__(self) -> str:
        return f"HashAlgorithm.{self._p4_name}"


class HashAlgorithm:
    csum16 = _HashAlgorithm("csum16")


class _ChecksumExtern:
    """A v1model checksum extern (verify_checksum or update_checksum)."""

    def __init__(self, name: str) -> None:
        self._p4_kind = "checksum_extern"
        self._p4_name = name

    def __call__(self, **kwargs):
        # Called at DSL capture time; the compiler reads the AST, not this.
        pass

    def __repr__(self) -> str:
        return self._p4_name


verify_checksum = _ChecksumExtern("verify_checksum")
update_checksum = _ChecksumExtern("update_checksum")


class _DirectCounter:
    """A v1model direct counter attached to a table."""

    def __init__(self, counter_type: str) -> None:
        self._p4_name = "direct_counter"
        self._p4_counter_type = counter_type
        self._p4_kind = "direct_counter"

    def __repr__(self) -> str:
        return f"direct_counter(CounterType.{self._p4_counter_type})"


def direct_counter(counter_type: str) -> _DirectCounter:
    """Create a v1model direct_counter."""
    return _DirectCounter(counter_type)


class _DirectMeter:
    """A v1model direct meter attached to a table."""

    def __init__(self, result_type, meter_type: str) -> None:
        self._p4_name = "direct_meter"
        self._p4_meter_type = meter_type
        self._p4_result_type = result_type
        self._p4_kind = "direct_meter"

    def __repr__(self) -> str:
        return f"direct_meter<{self._p4_result_type._p4_name}>(MeterType.{self._p4_meter_type})"


def direct_meter(result_type, meter_type: str) -> _DirectMeter:
    """Create a v1model direct_meter."""
    return _DirectMeter(result_type, meter_type)


class _CloneType:
    def __init__(self, name: str) -> None:
        self._p4_name = name

    def __repr__(self) -> str:
        return f"CloneType.{self._p4_name}"


class CloneType:
    I2E = _CloneType("I2E")
    E2E = _CloneType("E2E")


def clone(clone_type: _CloneType, session_id: int) -> None:
    """v1model clone extern. Called at DSL capture time; compiler reads AST."""
    pass


class V1ModelArch(Architecture):
    @property
    def include(self) -> str:
        return "v1model.p4"

    @property
    def pipeline(self) -> tuple[BlockSpec, ...]:
        return (
            BlockSpec("parser", "parser"),
            BlockSpec("verify_checksum", "control", required=False),
            BlockSpec("ingress", "control"),
            BlockSpec("egress", "control", required=False),
            BlockSpec("compute_checksum", "control", required=False),
            BlockSpec("deparser", "deparser"),
        )

    def block_signature(self, block_name, struct_names, param_names=()):
        ht = struct_names["headers"]
        mt = struct_names["metadata"]
        if block_name == "parser":
            # parser(packet_in, out headers, inout meta, inout standard_metadata_t)
            pkt, h, m, sm = (
                param_names
                if len(param_names) == 4
                else ("pkt", "hdr", "meta", "std_meta")
            )
            return (
                f"parser {{name}}(packet_in {pkt},\n"
                f"                out {ht} {h},\n"
                f"                inout {mt} {m},\n"
                f"                inout standard_metadata_t {sm})"
            )
        if block_name in ("verify_checksum", "compute_checksum"):
            # control(inout headers, inout meta)
            h, m = param_names if len(param_names) == 2 else ("hdr", "meta")
            return f"control {{name}}(inout {ht} {h}, inout {mt} {m})"
        if block_name == "deparser":
            # control(packet_out, in headers)
            pkt, h = param_names if len(param_names) == 2 else ("pkt", "hdr")
            return f"control {{name}}(packet_out {pkt}, in {ht} {h})"
        # ingress, egress: control(inout headers, inout meta, inout standard_metadata_t)
        h, m, sm = param_names if len(param_names) == 3 else ("hdr", "meta", "std_meta")
        return (
            f"control {{name}}(inout {ht} {h},\n"
            f"                  inout {mt} {m},\n"
            f"                  inout standard_metadata_t {sm})"
        )

    def main_instantiation(self, block_names):
        names = []
        for spec in self.pipeline:
            names.append(f"    {block_names[spec.name]}()")
        return "V1Switch(\n" + ",\n".join(names) + "\n) main;"

    def emit_boilerplate(self, lines, spec, struct_names):
        ht = struct_names["headers"]
        mt = struct_names["metadata"]
        if spec.name in ("verify_checksum", "compute_checksum"):
            cap = (
                "MyVerifyChecksum"
                if spec.name == "verify_checksum"
                else "MyComputeChecksum"
            )
            lines.append(f"control {cap}(inout {ht} h, inout {mt} m) {{")
            lines.append("    apply {}")
            lines.append("}")
            lines.append("")
        elif spec.name == "egress":
            lines.append(f"control MyEgress(inout {ht} h,")
            lines.append(f"                  inout {mt} m,")
            lines.append("                  inout standard_metadata_t sm) {")
            lines.append("    apply {}")
            lines.append("}")
            lines.append("")

    def process_packet(self, package, engine_cls, packet, ingress_port, table_entries):
        from p4py.sim import SimResult

        eng = engine_cls(package, packet, table_entries)

        # Initialize v1model standard metadata.
        eng.state.metadata["ingress_port"] = ingress_port
        eng.state.metadata["egress_spec"] = 0
        eng.state.metadata_widths["ingress_port"] = 9
        eng.state.metadata_widths["egress_spec"] = 9

        eng.register_extern("mark_to_drop", self._mark_to_drop(eng))
        eng.register_extern("verify_checksum", self._verify_checksum(eng))
        eng.register_extern("update_checksum", self._update_checksum(eng))
        eng.register_extern("clone", lambda stmt: None)

        eng.run_parser(_get_block(package, "parser"))

        vc = _get_block(package, "verify_checksum")
        if vc is not None:
            eng.run_control(vc)

        eng.run_control(_get_block(package, "ingress"))

        if eng.state.metadata["egress_spec"] == _DROP_PORT:
            return SimResult(packet=None, egress_port=_DROP_PORT, dropped=True)

        egress = _get_block(package, "egress")
        if egress is not None:
            eng.run_control(egress)

        cc = _get_block(package, "compute_checksum")
        if cc is not None:
            eng.run_control(cc)

        output = eng.run_deparser(_get_block(package, "deparser"))
        return SimResult(
            packet=output,
            egress_port=eng.state.metadata["egress_spec"],
            dropped=False,
        )

    @staticmethod
    def _mark_to_drop(engine):
        def handler(stmt):
            engine.state.metadata["egress_spec"] = _DROP_PORT

        return handler

    @staticmethod
    def _verify_checksum(engine):
        def handler(stmt):
            pass  # No-op in simulation.

        return handler

    @staticmethod
    def _update_checksum(engine):
        def handler(stmt):
            from p4py.sim.engine import compute_csum16

            cond_val = engine.eval_expression(stmt.args[0])
            if not cond_val:
                return
            data_list = stmt.args[1]  # ListExpression
            field_values = []
            for fa in data_list.elements:
                value = engine.eval_expression(fa)
                width = engine.resolve_field_width(fa)
                field_values.append((value, width))
            checksum = compute_csum16(field_values)
            engine.set_field(stmt.args[2], checksum)

        return handler


_V1MODEL_ARCH = V1ModelArch()


@dataclass
class V1Switch:
    """v1model pipeline with field order matching v1model.p4.

    Header and metadata types are inferred from the parser's type
    annotations (``hdr`` and ``meta`` parameters), matching how the
    real v1model architecture works.

    Optional blocks (verify_checksum, egress, compute_checksum) default
    to None; the P4-16 emitter produces empty apply blocks for them.
    """

    parser: _Spec | None = None
    verify_checksum: _Spec | None = None
    ingress: _Spec | None = None
    egress: _Spec | None = None
    compute_checksum: _Spec | None = None
    deparser: _Spec | None = None
    declarations: tuple = ()

    def __post_init__(self) -> None:
        self.arch: Architecture = _V1MODEL_ARCH
        if self.parser is not None:
            # Extract by position: parser(pkt, headers, [metadata], std_meta)
            ann_values = list(self.parser._p4_annotations.values())
            self.headers: type[p4.struct] = ann_values[0] if ann_values else None
            self.metadata: type[p4.struct] = (
                ann_values[1] if len(ann_values) > 1 else None
            )
