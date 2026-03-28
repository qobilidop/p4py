"""P4 type definitions: bit, header, struct, and core built-ins."""

from __future__ import annotations

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

    Subclass and annotate members with header subclasses:

        class headers_t(struct):
            ethernet: ethernet_t
            ipv4: ipv4_t

    Empty structs (e.g., metadata) are allowed.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        members: list[tuple[str, type]] = []
        for name, ann in cls.__annotations__.items():
            if not (isinstance(ann, type) and issubclass(ann, header)):
                raise TypeError(
                    f"Struct member '{name}' must be a header subclass, got {ann!r}"
                )
            members.append((name, ann))
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

ACCEPT = "accept"
REJECT = "reject"
