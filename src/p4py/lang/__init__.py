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
    BoolType,
    NoAction,
    bit,
    exact,
    header,
    hex,
    literal,
    lpm,
    struct,
)
from p4py.lang._types import (
    bool_ as bool,
)

__all__ = [
    "ACCEPT",
    "REJECT",
    "BitType",
    "BoolType",
    "NoAction",
    "_Spec",
    "action",
    "bit",
    "bool",
    "control",
    "deparser",
    "exact",
    "header",
    "hex",
    "literal",
    "lpm",
    "parser",
    "struct",
    "table",
]
