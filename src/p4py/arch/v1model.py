"""v1model architecture for P4Mini.

Defines the minimal v1model subset: standard_metadata_t, mark_to_drop,
and V1SwitchMini pipeline.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from p4py.lang.bit import bit
from p4py.lang.header import header

if TYPE_CHECKING:
    from p4py.lang import _Spec
    from p4py.lang.struct import struct as struct_cls


class standard_metadata_t(header):
    ingress_port: bit(9)
    egress_spec: bit(9)


class _Extern:
    """A v1model extern function."""

    def __init__(self, name: str) -> None:
        self._p4_kind = "extern"
        self._p4_name = name

    def __repr__(self) -> str:
        return self._p4_name


mark_to_drop = _Extern("mark_to_drop")


@dataclass
class V1SwitchMini:
    """Simplified v1model pipeline: Parser, Ingress, Deparser.

    Header and metadata types are inferred from the parser's type
    annotations (``hdr`` and ``meta`` parameters), matching how the
    real v1model architecture works.

    The P4-16 emitter expands this to the full V1Switch with empty
    VerifyChecksum, Egress, and ComputeChecksum blocks.
    """

    parser: "_Spec"
    ingress: "_Spec"
    deparser: "_Spec"

    def __post_init__(self) -> None:
        annotations = self.parser._p4_annotations
        self.headers: type[struct_cls] = annotations["hdr"]
        self.metadata: type[struct_cls] = annotations["meta"]
