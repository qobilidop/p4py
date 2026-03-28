"""bit<W> fixed-width unsigned integer type."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache


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
