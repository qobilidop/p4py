"""P4Py language surface.

Idiomatic usage: import p4py.lang as p4
"""

from p4py.lang._blocks import (
    _Spec,
    action,
    control,
    deparser,
    parser,
    table,
)
from p4py.lang._types import (
    ACCEPT,
    REJECT,
    BitType,
    bit,
    exact,
    header,
    lpm,
    struct,
)

__all__ = [
    "ACCEPT",
    "REJECT",
    "BitType",
    "_Spec",
    "action",
    "bit",
    "control",
    "deparser",
    "exact",
    "header",
    "lpm",
    "parser",
    "struct",
    "table",
]
