"""v1model architecture for P4Mini.

Defines the minimal v1model subset: standard_metadata_t, mark_to_drop,
and V1Switch pipeline.
"""

from dataclasses import dataclass

import p4py.lang as p4
from p4py.lang import _Spec


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

    def __post_init__(self) -> None:
        if self.parser is not None:
            annotations = self.parser._p4_annotations
            self.headers: type[p4.struct] = annotations.get("hdr")
            self.metadata: type[p4.struct] = annotations.get("meta")
