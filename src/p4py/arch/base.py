"""Architecture base classes.

Defines the abstract interface that all P4 architectures implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class BlockSpec:
    """Specification for a pipeline block."""

    name: str
    kind: str  # "parser", "control", "deparser"
    required: bool = True


class Architecture(ABC):
    """Abstract P4 architecture.

    Each architecture (v1model, ebpf_model, etc.) implements this interface
    to define its pipeline shape, P4 emission details, and simulation behavior.
    """

    @property
    @abstractmethod
    def include(self) -> str:
        """Architecture header file name, e.g. 'v1model.p4'."""

    @property
    @abstractmethod
    def pipeline(self) -> tuple[BlockSpec, ...]:
        """Ordered pipeline block specifications."""

    @abstractmethod
    def block_signature(
        self,
        block_name: str,
        struct_names: dict[str, str],
        param_names: tuple[str, ...] = (),
    ) -> str:
        """Return the P4 signature string for a pipeline block."""

    @abstractmethod
    def main_instantiation(self, block_names: dict[str, str]) -> str:
        """Return the main package instantiation line."""

    @abstractmethod
    def emit_boilerplate(
        self, lines: list[str], spec: BlockSpec, struct_names: dict[str, str]
    ) -> None:
        """Emit an empty block for a missing optional pipeline stage."""

    @abstractmethod
    def process_packet(
        self,
        package,
        engine_cls,
        packet,
        ingress_port,
        table_entries,
        clone_session_map=None,
    ):
        """Simulate a packet through the architecture's pipeline."""
