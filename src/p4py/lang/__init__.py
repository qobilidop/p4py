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
    struct,
)

__all__ = [
    "ACCEPT",
    "REJECT",
    "BitType",
    "action",
    "bit",
    "control",
    "deparser",
    "exact",
    "header",
    "parser",
    "struct",
    "table",
]
