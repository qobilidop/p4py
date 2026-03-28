"""P4Py language surface.

Idiomatic usage: import p4py.lang as p4
"""

import inspect
import textwrap

from p4py.lang.bit import bit
from p4py.lang.core import ACCEPT, REJECT, exact
from p4py.lang.header import header
from p4py.lang.struct import struct


class _Spec:
    """A captured P4 block (parser, control, or deparser)."""

    def __init__(self, kind: str, name: str, source: str) -> None:
        self._p4_kind = kind
        self._p4_name = name
        self._p4_source = source


def _make_decorator(kind: str):
    def decorator(func):
        source = textwrap.dedent(inspect.getsource(func))
        return _Spec(kind=kind, name=func.__name__, source=source)

    return decorator


parser = _make_decorator("parser")
control = _make_decorator("control")
deparser = _make_decorator("deparser")


class _Sentinel:
    """A sentinel object recognized by the AST parser."""

    def __init__(self, kind: str, name: str) -> None:
        self._p4_kind = kind
        self._p4_name = name

    def __repr__(self) -> str:
        return self._p4_name


action = _Sentinel("decorator", "action")
table = _Sentinel("builtin", "table")

__all__ = [
    "ACCEPT",
    "REJECT",
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
