"""Tests for the P4Mini simulator."""

import p4py.lang as p4
from p4py.arch.v1model import V1SwitchMini, mark_to_drop
from p4py.compiler import compile
from p4py.lang.bit import bit
from p4py.lang.header import header
from p4py.lang.struct import struct
from p4py.sim import simulate


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


def _make_ipv4_forwarder():
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

    pipeline = V1SwitchMini(
        headers=headers_t,
        metadata=metadata_t,
        parser=MyParser,
        ingress=MyIngress,
        deparser=MyDeparser,
    )
    return compile(pipeline)


# A minimal Ethernet + IPv4 packet for testing.
ETHERNET_HDR = (
    b"\x00\x00\x00\x00\x00\x01"  # dstAddr
    b"\x00\x00\x00\x00\x00\x02"  # srcAddr
    b"\x08\x00"  # etherType = 0x0800
)
IPV4_HDR = (
    b"\x45"  # version=4, ihl=5
    b"\x00"  # diffserv
    b"\x00\x14"  # totalLen=20
    b"\x00\x00"  # identification
    b"\x00\x00"  # flags=0, fragOffset=0
    b"\x40"  # ttl=64
    b"\x06"  # protocol=6 (TCP)
    b"\x00\x00"  # hdrChecksum
    b"\x0a\x00\x00\x01"  # srcAddr=10.0.0.1
    b"\x0a\x00\x00\x02"  # dstAddr=10.0.0.2
)
TEST_PACKET = ETHERNET_HDR + IPV4_HDR


class TestSimulator:
    def test_forward_packet(self):
        program = _make_ipv4_forwarder()
        table_entries = {
            "ipv4_table": [
                {
                    "key": {"hdr.ipv4.dstAddr": 0x0A000002},
                    "action": "forward",
                    "args": {"port": 2},
                },
            ],
        }
        result = simulate(
            program,
            packet=TEST_PACKET,
            ingress_port=1,
            table_entries=table_entries,
        )
        assert result.egress_port == 2
        assert result.packet is not None
        # TTL should be decremented from 64 to 63.
        assert result.packet[22] == 63

    def test_drop_on_table_miss(self):
        program = _make_ipv4_forwarder()
        result = simulate(
            program,
            packet=TEST_PACKET,
            ingress_port=1,
            table_entries={},
        )
        assert result.dropped

    def test_drop_non_ipv4(self):
        # Non-IPv4 packet (etherType=0x0806 ARP).
        arp_packet = (
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x06" + b"\x00" * 28
        )
        program = _make_ipv4_forwarder()
        result = simulate(
            program,
            packet=arp_packet,
            ingress_port=1,
            table_entries={},
        )
        assert result.dropped
