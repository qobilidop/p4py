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


# --- _NamedType: typedef and newtype ---


class _NamedType:
    """A named alias or distinct type wrapping a BitType."""

    def __init__(self, underlying: BitType, name: str, kind: str) -> None:
        self._p4_underlying = underlying
        self._p4_name = name
        self._p4_kind = kind
        self.width = underlying.width

    def __repr__(self) -> str:
        return self._p4_name


def typedef(underlying: BitType, name: str) -> _NamedType:
    """Create a P4 typedef: typedef bit<W> name."""
    return _NamedType(underlying, name, "typedef")


def newtype(underlying: BitType, name: str) -> _NamedType:
    """Create a P4 type: type bit<W> name."""
    return _NamedType(underlying, name, "newtype")


def var(named_type: _NamedType) -> _NamedType:
    """Declare a zero-initialized local variable of a named type."""
    return named_type


# --- enum ---


def enum(underlying: BitType):
    """Return a base class for a P4 serializable enum.

    Usage:
        class Color_t(p4.enum(p4.bit(2))):
            GREEN = 0
            YELLOW = 1
    """

    class _EnumBase:
        def __init_subclass__(cls, **kwargs: object) -> None:
            super().__init_subclass__(**kwargs)
            members = []
            for attr, val in cls.__dict__.items():
                if not attr.startswith("_") and isinstance(val, int):
                    members.append((attr, val))
            cls._p4_name = cls.__name__
            cls._p4_underlying = underlying
            cls._p4_members = tuple(members)
            cls._p4_kind = "enum"
            cls.width = underlying.width

    return _EnumBase


# --- _Const ---


class _Const:
    """A P4 compile-time constant."""

    def __init__(self, type_name: str, value: int, name: str) -> None:
        self._p4_type_name = type_name
        self._p4_value = value
        self._p4_name = name
        self._p4_kind = "const"

    def __repr__(self) -> str:
        return self._p4_name


def const(type_ref: _NamedType | BitType, value: int, name: str) -> _Const:
    """Create a P4 const declaration."""
    if isinstance(type_ref, BitType):
        type_name = f"bit<{type_ref.width}>"
    else:
        type_name = type_ref._p4_name
    return _Const(type_name, value, name)


# --- header ---


def _is_bit_like(ann: object) -> bool:
    """Return True if ann is a BitType or a _NamedType (typedef/newtype)."""
    return isinstance(ann, (BitType, _NamedType))


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
        fields: list[tuple[str, BitType | _NamedType]] = []
        for name, ann in cls.__annotations__.items():
            if not _is_bit_like(ann):
                raise TypeError(
                    f"Header field '{name}' must be annotated with bit(W), got {ann!r}"
                )
            fields.append((name, ann))
        if not fields:
            raise TypeError(f"Header '{cls.__name__}' must have at least one field")
        cls._p4_name = cls.__name__
        cls._p4_fields = tuple(fields)
        cls._p4_bit_width = sum(ann.width for _, ann in fields)


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
        members: list[tuple[str, type | BitType | _NamedType]] = []
        for name, ann in cls.__annotations__.items():
            is_p4_type = (
                isinstance(ann, (BitType, BoolType, _NamedType))
                or (isinstance(ann, type) and issubclass(ann, (header, struct)))
                or (
                    isinstance(ann, type)
                    and hasattr(ann, "_p4_kind")
                    and ann._p4_kind == "enum"
                )
            )
            if is_p4_type:
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
optional = _MatchKind("optional")
selector = _MatchKind("selector")


# --- action_selector ---


class _ActionSelector:
    """An action_selector declaration."""

    def __init__(self, algorithm, size: int, width: int) -> None:
        self._p4_algorithm = repr(algorithm) if hasattr(algorithm, '_p4_name') else str(algorithm)
        self._p4_size = size
        self._p4_width = width
        self._p4_kind = "action_selector"

    def __repr__(self) -> str:
        return f"action_selector({self._p4_algorithm}, {self._p4_size}, {self._p4_width})"


def action_selector(algorithm, size: int, width: int) -> _ActionSelector:
    """Create a P4 action_selector declaration."""
    return _ActionSelector(algorithm, size, width)


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


def cast(type_ref, value):
    """Type cast expression. Emits as ``(type) expr`` in P4."""
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


class _ActionDecorator(_Sentinel):
    """Works as both @p4.action decorator (file scope) and AST sentinel."""

    def __call__(self, func):
        source = textwrap.dedent(inspect.getsource(func))
        annotations = {
            k: v for k, v in func.__annotations__.items() if k != "return"
        }
        return _Spec(
            kind="action", name=func.__name__, source=source,
            annotations=annotations,
        )


action = _ActionDecorator("decorator", "action")
table = _Sentinel("builtin", "table")


# --- Parameter directions ---


class _Direction:
    """A parameter direction wrapper."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __call__(self, type_ref):
        """Wrap a type with a direction: p4.in_(headers_t)."""
        return _DirectedType(self._name, type_ref)

    def __repr__(self) -> str:
        return self._name


class _DirectedType:
    """A type with a direction annotation."""

    def __init__(self, direction: str, type_ref) -> None:
        self.direction = direction
        self.type_ref = type_ref
        # Delegate _p4_name to the underlying type.
        if hasattr(type_ref, "_p4_name"):
            self._p4_name = type_ref._p4_name


in_ = _Direction("in")
out_ = _Direction("out")
out = out_
inout_ = _Direction("inout")
inout = inout_


def __getattr__(name):
    if name == "in":
        return in_
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
