"""P4Py language surface.

Idiomatic usage: import p4py.lang as p4
"""

from __future__ import annotations

import inspect
import textwrap
from dataclasses import dataclass
from functools import lru_cache

# --- bit<W> ---


@lru_cache(maxsize=256)
def bit(width: int) -> BitType:
    """Create a bit<W> type. Cached so that bit(8) is bit(8)."""
    if not isinstance(width, int) or width <= 0:
        raise ValueError(f"bit width must be a positive integer, got {width}")
    return BitType(width)


@dataclass(frozen=True)
class BitType:
    """A fixed-width unsigned integer type, like P4's bit<W>."""

    width: int

    def __repr__(self) -> str:
        return f"bit({self.width})"


# --- header ---


class header:
    """Base class for P4 header types.

    Subclass and annotate fields with bit(W):

        class ethernet_t(header):
            dstAddr: bit(48)
            srcAddr: bit(48)
            etherType: bit(16)
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        fields: list[tuple[str, BitType]] = []
        for name, ann in cls.__annotations__.items():
            if not isinstance(ann, BitType):
                raise TypeError(
                    f"Header field '{name}' must be annotated with bit(W), got {ann!r}"
                )
            fields.append((name, ann))
        if not fields:
            raise TypeError(f"Header '{cls.__name__}' must have at least one field")
        cls._p4_name = cls.__name__
        cls._p4_fields = tuple(fields)
        cls._p4_bit_width = sum(f.width for _, f in fields)


# --- struct ---


class struct:
    """Base class for P4 struct types.

    Subclass and annotate members with header subclasses or bit<W> types:

        class headers_t(struct):
            ethernet: ethernet_t
            ipv4: ipv4_t

        class metadata_t(struct):
            vrf: p4.bit(12)

    Empty structs are allowed.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        members: list[tuple[str, type | BitType]] = []
        for name, ann in cls.__annotations__.items():
            if isinstance(ann, BitType) or (
                isinstance(ann, type) and issubclass(ann, (header, struct))
            ):
                members.append((name, ann))
            else:
                raise TypeError(
                    f"Struct member '{name}' must be a header subclass,"
                    f" struct subclass, or bit<W>, got {ann!r}"
                )
        cls._p4_name = cls.__name__
        cls._p4_members = tuple(members)


# --- core.p4 built-ins ---


class _MatchKind:
    """Sentinel for match kinds."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __repr__(self) -> str:
        return self._name


exact = _MatchKind("exact")
lpm = _MatchKind("lpm")
ternary = _MatchKind("ternary")


# --- bool ---


class BoolType:
    """P4's bool type."""

    def __repr__(self) -> str:
        return "bool"


# Module-level singleton; users write p4.bool.
# Named bool_ to avoid shadowing Python's built-in bool.
bool_ = BoolType()
bool = bool_


# --- built-in actions ---


class _BuiltinAction:
    """A built-in P4 action (e.g., NoAction)."""

    def __init__(self, name: str) -> None:
        self._p4_name = name

    def __repr__(self) -> str:
        return self._p4_name


NoAction = _BuiltinAction("NoAction")


def literal(value: int, *, width: int) -> int:
    """Width-annotated integer literal. Emits as ``<width>w<value>`` in P4."""
    return value


def hex(value: int) -> int:
    """Hex-formatted integer literal. Emits as ``0x...`` in P4."""
    return value


def mask(value: int, mask: int) -> int:
    """Masked value for const entries. Emits as ``value &&& mask`` in P4."""
    return value


ACCEPT = "accept"
REJECT = "reject"


# --- Block definitions: parser, control, deparser, and DSL sentinels ---


class _Spec:
    """A captured P4 block (parser, control, or deparser)."""

    def __init__(self, kind: str, name: str, source: str, annotations: dict) -> None:
        self._p4_kind = kind
        self._p4_name = name
        self._p4_source = source
        self._p4_annotations = annotations


def _make_decorator(kind: str):
    def decorator(func):
        source = textwrap.dedent(inspect.getsource(func))
        annotations = {k: v for k, v in func.__annotations__.items() if k != "return"}
        return _Spec(
            kind=kind, name=func.__name__, source=source, annotations=annotations
        )

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
