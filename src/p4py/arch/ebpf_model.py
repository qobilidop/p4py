"""eBPF filter architecture for P4Py.

Defines the ebpfFilter pipeline: a parser and a filter control.
Matches the ebpf_model.p4 architecture definition.
"""

from dataclasses import dataclass

import p4py.lang as p4
from p4py.lang import _Spec


class _TableImpl:
    """An eBPF table implementation extern (hash_table or array_table)."""

    def __init__(self, name: str, size: int) -> None:
        self._p4_kind = "table_impl"
        self._p4_name = name
        self._p4_size = size

    def __repr__(self) -> str:
        return f"{self._p4_name}({self._p4_size})"


def hash_table(size: int) -> _TableImpl:
    """Create a hash_table implementation property."""
    return _TableImpl("hash_table", size)


def array_table(size: int) -> _TableImpl:
    """Create an array_table implementation property."""
    return _TableImpl("array_table", size)


@dataclass
class ebpfFilter:
    """eBPF filter pipeline with field order matching ebpf_model.p4.

    Header types are inferred from the parser's type annotations
    (``headers`` parameter).
    """

    parser: _Spec | None = None
    filter: _Spec | None = None

    def __post_init__(self) -> None:
        if self.parser is not None:
            annotations = self.parser._p4_annotations
            self.headers: type[p4.struct] = annotations.get("headers")
