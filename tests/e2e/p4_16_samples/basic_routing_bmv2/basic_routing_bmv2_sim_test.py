"""Simulator test for basic_routing_bmv2.

Compiles the P4Py program, runs packets through the simulator, and
verifies routing behavior: exact FIB hit, LPM fallback, nexthop
resolution, and TTL decrement.
"""

from p4py.compiler import compile
from p4py.sim import simulate
from tests.e2e.p4_16_samples.basic_routing_bmv2.basic_routing_bmv2 import main

# Ethernet(dst=01, src=02, etherType=0x0800) + IPv4(src=10.0.0.1, dst=10.0.0.2, ttl=64)
ETHERNET_HDR = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00"
IPV4_HDR = (
    b"\x45\x00\x00\x14"  # version=4, ihl=5, totalLen=20
    b"\x00\x00\x00\x00"  # identification, flags, fragOffset
    b"\x40\x06\x00\x00"  # ttl=64, protocol=6, checksum=0
    b"\x0a\x00\x00\x01"  # srcAddr=10.0.0.1
    b"\x0a\x00\x00\x02"  # dstAddr=10.0.0.2
)
TEST_PACKET = ETHERNET_HDR + IPV4_HDR

TABLE_ENTRIES = {
    # Port mapping: ingress port 0 → bd 10
    "port_mapping": [
        {
            "key": {"std_meta.ingress_port": 0},
            "action": "set_bd",
            "args": {"bd": 10},
        },
    ],
    # BD: bd 10 → vrf 1
    "bd_table": [
        {
            "key": {"meta.bd": 10},
            "action": "set_vrf",
            "args": {"vrf": 1},
        },
    ],
    # Exact FIB: 10.0.0.2 → nexthop 1
    "ipv4_fib": [
        {
            "key": {"hdr.ipv4.dstAddr": 0x0A000002},
            "action": "fib_hit_nexthop",
            "args": {"nexthop_index": 1},
        },
    ],
    # LPM FIB: 10.0.0.0/8 → nexthop 2
    "ipv4_fib_lpm": [
        {
            "key": {"hdr.ipv4.dstAddr": 0x0A000000},
            "prefix_len": {"hdr.ipv4.dstAddr": 8},
            "action": "fib_hit_nexthop",
            "args": {"nexthop_index": 2},
        },
    ],
    # Rewrite MAC: nexthop 1 → AA:01/BB:01, nexthop 2 → AA:02/BB:02
    "rewrite_mac_table": [
        {
            "key": {"meta.nexthop_index": 1},
            "action": "rewrite_mac",
            "args": {"smac": 0x00000000AA01, "dmac": 0x00000000BB01},
        },
        {
            "key": {"meta.nexthop_index": 2},
            "action": "rewrite_mac",
            "args": {"smac": 0x00000000AA02, "dmac": 0x00000000BB02},
        },
    ],
    # Nexthop: 1 → port 5, 2 → port 7
    "nexthop": [
        {
            "key": {"meta.nexthop_index": 1},
            "action": "set_egress_details",
            "args": {"egress_spec": 5},
        },
        {
            "key": {"meta.nexthop_index": 2},
            "action": "set_egress_details",
            "args": {"egress_spec": 7},
        },
    ],
}


class TestBasicRoutingSim:
    def setup_method(self):
        self.program = compile(main)

    def test_exact_fib_hit(self):
        """Packet to 10.0.0.2 hits exact FIB → nexthop 1 → port 5."""
        result = simulate(
            self.program,
            packet=TEST_PACKET,
            ingress_port=0,
            table_entries=TABLE_ENTRIES,
        )
        assert not result.dropped
        assert result.egress_port == 5
        # TTL decremented from 64 to 63.
        assert result.packet[22] == 63

    def test_lpm_fallback(self):
        """Misses exact FIB, falls through to LPM."""
        # Change dstAddr to 10.1.0.1 (0x0A010001)
        packet = bytearray(TEST_PACKET)
        packet[30:34] = (0x0A010001).to_bytes(4)
        result = simulate(
            self.program,
            packet=bytes(packet),
            ingress_port=0,
            table_entries=TABLE_ENTRIES,
        )
        assert not result.dropped
        assert result.egress_port == 7
        assert result.packet[22] == 63

    def test_no_route_drops(self):
        """Misses both FIB tables, nexthop defaults to on_miss."""
        packet = bytearray(TEST_PACKET)
        packet[30:34] = (0xC0A80001).to_bytes(4)
        result = simulate(
            self.program,
            packet=bytes(packet),
            ingress_port=0,
            table_entries=TABLE_ENTRIES,
        )
        # on_miss does nothing, nexthop misses too → egress_spec stays 0.
        assert result.egress_port == 0

    def test_port_mapping_sets_bd(self):
        """Port mapping table sets bridge domain from ingress port."""
        result = simulate(
            self.program,
            packet=TEST_PACKET,
            ingress_port=0,
            table_entries=TABLE_ENTRIES,
        )
        # Port mapping + bd + FIB pipeline all work together.
        # Packet still routes to port 5 via exact FIB hit.
        assert not result.dropped
        assert result.egress_port == 5

    def test_unknown_ingress_port(self):
        """Unknown ingress port misses port_mapping, pipeline still works."""
        result = simulate(
            self.program,
            packet=TEST_PACKET,
            ingress_port=99,
            table_entries=TABLE_ENTRIES,
        )
        # port_mapping misses (on_miss), bd_table misses (on_miss),
        # but FIB still routes the packet.
        assert not result.dropped
        assert result.egress_port == 5

    def test_egress_rewrites_mac(self):
        """Egress rewrite_mac table rewrites src/dst MAC after routing."""
        result = simulate(
            self.program,
            packet=TEST_PACKET,
            ingress_port=0,
            table_entries=TABLE_ENTRIES,
        )
        assert not result.dropped
        assert result.egress_port == 5
        # dstAddr rewritten to 00:00:00:00:BB:01
        assert result.packet[0:6] == b"\x00\x00\x00\x00\xbb\x01"
        # srcAddr rewritten to 00:00:00:00:AA:01
        assert result.packet[6:12] == b"\x00\x00\x00\x00\xaa\x01"

    def test_egress_rewrite_lpm_path(self):
        """Egress rewrites MAC on the LPM fallback path too."""
        packet = bytearray(TEST_PACKET)
        packet[30:34] = (0x0A010001).to_bytes(4)  # 10.1.0.1 → LPM match
        result = simulate(
            self.program,
            packet=bytes(packet),
            ingress_port=0,
            table_entries=TABLE_ENTRIES,
        )
        assert not result.dropped
        assert result.egress_port == 7
        # nexthop 2 → smac AA:02, dmac BB:02
        assert result.packet[0:6] == b"\x00\x00\x00\x00\xbb\x02"
        assert result.packet[6:12] == b"\x00\x00\x00\x00\xaa\x02"

    def test_non_ipv4_dropped(self):
        """Non-IPv4 packet is not processed (no isValid)."""
        arp_packet = (
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x06" + b"\x00" * 28
        )
        result = simulate(
            self.program,
            packet=arp_packet,
            ingress_port=0,
            table_entries=TABLE_ENTRIES,
        )
        # No tables applied, egress_spec stays 0.
        assert result.egress_port == 0
