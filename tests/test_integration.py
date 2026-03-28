"""End-to-end integration test: IPv4 forwarder in P4Py.

Writes the test program from the P4Mini spec using the full DSL, compiles to IR,
emits P4-16 source, and simulates packet processing.
"""

import p4py.lang as p4
from p4py.arch.v1model import V1SwitchMini, mark_to_drop
from p4py.backend.p4 import emit
from p4py.compiler import compile
from p4py.lang.bit import bit
from p4py.lang.header import header
from p4py.lang.struct import struct
from p4py.sim import simulate

# --- Type definitions ---


class ethernet_t(header):
    dstAddr: bit(48)
    srcAddr: bit(48)
    etherType: bit(16)


class ipv4_t(header):
    version: bit(4)
    ihl: bit(4)
    diffserv: bit(8)
    totalLen: bit(16)
    identification: bit(16)
    flags: bit(3)
    fragOffset: bit(13)
    ttl: bit(8)
    protocol: bit(8)
    hdrChecksum: bit(16)
    srcAddr: bit(32)
    dstAddr: bit(32)


class headers_t(struct):
    ethernet: ethernet_t
    ipv4: ipv4_t


class metadata_t(struct):
    pass


# --- P4 program ---


@p4.parser
def MyParser(pkt, hdr, meta, std_meta):
    def start():
        pkt.extract(hdr.ethernet)
        match hdr.ethernet.etherType:
            case 0x0800:
                return parse_ipv4
            case _:
                return p4.ACCEPT

    def parse_ipv4():
        pkt.extract(hdr.ipv4)
        return p4.ACCEPT


@p4.control
def MyIngress(hdr, meta, std_meta):
    @p4.action
    def forward(port: p4.bit(9)):
        std_meta.egress_spec = port
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1

    @p4.action
    def drop():
        mark_to_drop(std_meta)

    ipv4_table = p4.table(
        key={hdr.ipv4.dstAddr: p4.exact},
        actions=[forward, drop],
        default_action=drop,
    )

    if hdr.ipv4.isValid():
        ipv4_table.apply()
    else:
        drop()


@p4.deparser
def MyDeparser(pkt, hdr):
    pkt.emit(hdr.ethernet)
    pkt.emit(hdr.ipv4)


main = V1SwitchMini(
    headers=headers_t,
    metadata=metadata_t,
    parser=MyParser,
    ingress=MyIngress,
    deparser=MyDeparser,
)

# --- Test packets ---

ETHERNET_HDR = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00"
IPV4_HDR = (
    b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
)
IPV4_PACKET = ETHERNET_HDR + IPV4_HDR
ARP_PACKET = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x06" + b"\x00" * 28

TABLE_ENTRIES = {
    "ipv4_table": [
        {
            "key": {"hdr.ipv4.dstAddr": 0x0A000002},
            "action": "forward",
            "args": {"port": 2},
        },
    ],
}


# --- Tests ---


class TestIntegration:
    def test_compile_and_emit(self):
        """Compile to IR and emit valid P4-16 source."""
        program = compile(main)
        source = emit(program)

        # Should be parseable P4 — check key structure.
        assert "header ethernet_t {" in source
        assert "header ipv4_t {" in source
        assert "parser MyParser(" in source
        assert "control MyIngress(" in source
        assert "V1Switch(" in source
        assert ") main;" in source

    def test_simulate_forward(self):
        """IPv4 packet matching a table entry is forwarded."""
        program = compile(main)
        result = simulate(
            program,
            packet=IPV4_PACKET,
            ingress_port=1,
            table_entries=TABLE_ENTRIES,
        )
        assert not result.dropped
        assert result.egress_port == 2
        # TTL decremented from 64 (0x40) to 63 (0x3f).
        assert result.packet[22] == 63

    def test_simulate_drop_no_entry(self):
        """IPv4 packet with no matching entry is dropped."""
        program = compile(main)
        result = simulate(
            program,
            packet=IPV4_PACKET,
            ingress_port=1,
            table_entries={},
        )
        assert result.dropped

    def test_simulate_drop_non_ipv4(self):
        """Non-IPv4 packet is dropped (isValid check fails)."""
        program = compile(main)
        result = simulate(
            program,
            packet=ARP_PACKET,
            ingress_port=1,
            table_entries=TABLE_ENTRIES,
        )
        assert result.dropped
