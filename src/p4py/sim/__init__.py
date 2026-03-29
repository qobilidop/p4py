"""P4 simulator."""

from __future__ import annotations

from dataclasses import dataclass

from p4py import ir
from p4py.sim.engine import SimEngine


@dataclass
class SimResult:
    """Result of simulating a packet."""

    packet: bytes | None
    egress_port: int
    dropped: bool


def simulate(
    program: ir.Package,
    packet: bytes,
    ingress_port: int,
    table_entries: dict[str, list[dict]] | None = None,
) -> SimResult:
    """Simulate a packet through a P4 program."""
    if table_entries is None:
        table_entries = {}
    return program.arch.process_packet(
        program, SimEngine, packet, ingress_port, table_entries
    )
