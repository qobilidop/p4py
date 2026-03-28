"""Tests for the P4Mini simulator."""

import p4py.lang as p4
from p4py.arch.v1model import V1Switch, mark_to_drop
from p4py.compiler import compile
from p4py.sim import simulate


class ethernet_t(p4.header):
    dstAddr: p4.bit(48)
    srcAddr: p4.bit(48)
    etherType: p4.bit(16)


class ipv4_t(p4.header):
    version: p4.bit(4)
    ihl: p4.bit(4)
    diffserv: p4.bit(8)
    totalLen: p4.bit(16)
    identification: p4.bit(16)
    flags: p4.bit(3)
    fragOffset: p4.bit(13)
    ttl: p4.bit(8)
    protocol: p4.bit(8)
    hdrChecksum: p4.bit(16)
    srcAddr: p4.bit(32)
    dstAddr: p4.bit(32)


class headers_t(p4.struct):
    ethernet: ethernet_t
    ipv4: ipv4_t


class metadata_t(p4.struct):
    pass


def _make_passthrough():
    """A pipeline that parses ethernet+ipv4 but doesn't drop anything."""

    @p4.parser
    def MyParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
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
        def nop():
            pass

        t = p4.table(
            key={hdr.ethernet.dstAddr: p4.exact},
            actions=[nop],
            default_action=nop,
        )

        t.apply()

    @p4.deparser
    def MyDeparser(pkt, hdr):
        pkt.emit(hdr.ethernet)
        pkt.emit(hdr.ipv4)

    pipeline = V1Switch(
        parser=MyParser,
        ingress=MyIngress,
        deparser=MyDeparser,
    )
    return compile(pipeline)


def _make_ipv4_forwarder():
    @p4.parser
    def MyParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
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

    pipeline = V1Switch(
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

    def test_lpm_match(self):
        """LPM table matches the longest prefix."""

        @p4.parser
        def MyParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
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

            @p4.action
            def drop():
                mark_to_drop(std_meta)

            ipv4_lpm = p4.table(
                key={hdr.ipv4.dstAddr: p4.lpm},
                actions=[forward, drop],
                default_action=drop,
            )

            if hdr.ipv4.isValid():
                ipv4_lpm.apply()

        @p4.deparser
        def MyDeparser(pkt, hdr):
            pkt.emit(hdr.ethernet)
            pkt.emit(hdr.ipv4)

        program = compile(
            V1Switch(parser=MyParser, ingress=MyIngress, deparser=MyDeparser)
        )

        # 10.0.0.0/8 → port 1, 10.0.0.0/24 → port 2
        # Packet to 10.0.0.2 should match /24 (longest prefix).
        table_entries = {
            "ipv4_lpm": [
                {
                    "key": {"hdr.ipv4.dstAddr": 0x0A000000},
                    "prefix_len": {"hdr.ipv4.dstAddr": 8},
                    "action": "forward",
                    "args": {"port": 1},
                },
                {
                    "key": {"hdr.ipv4.dstAddr": 0x0A000000},
                    "prefix_len": {"hdr.ipv4.dstAddr": 24},
                    "action": "forward",
                    "args": {"port": 2},
                },
            ],
        }
        result = simulate(
            program, packet=TEST_PACKET, ingress_port=0, table_entries=table_entries
        )
        assert not result.dropped
        assert result.egress_port == 2

    def test_lpm_no_match(self):
        """LPM table falls through to default when no prefix matches."""

        @p4.parser
        def MyParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
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

            @p4.action
            def drop():
                mark_to_drop(std_meta)

            ipv4_lpm = p4.table(
                key={hdr.ipv4.dstAddr: p4.lpm},
                actions=[forward, drop],
                default_action=drop,
            )

            if hdr.ipv4.isValid():
                ipv4_lpm.apply()

        @p4.deparser
        def MyDeparser(pkt, hdr):
            pkt.emit(hdr.ethernet)
            pkt.emit(hdr.ipv4)

        program = compile(
            V1Switch(parser=MyParser, ingress=MyIngress, deparser=MyDeparser)
        )

        # Entry for 192.168.0.0/16, packet goes to 10.0.0.2 — no match.
        table_entries = {
            "ipv4_lpm": [
                {
                    "key": {"hdr.ipv4.dstAddr": 0xC0A80000},
                    "prefix_len": {"hdr.ipv4.dstAddr": 16},
                    "action": "forward",
                    "args": {"port": 1},
                },
            ],
        }
        result = simulate(
            program, packet=TEST_PACKET, ingress_port=0, table_entries=table_entries
        )
        assert result.dropped

    def test_switch_action_run(self):
        """Switch on action_run routes to fallback table on miss."""

        @p4.parser
        def MyParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
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
            def on_miss():
                pass

            @p4.action
            def forward(port: p4.bit(9)):
                std_meta.egress_spec = port

            # Exact table — miss triggers LPM fallback.
            ipv4_fib = p4.table(
                key={hdr.ipv4.dstAddr: p4.exact},
                actions=[on_miss, forward],
                default_action=on_miss,
            )

            ipv4_fib_lpm = p4.table(
                key={hdr.ipv4.dstAddr: p4.lpm},
                actions=[on_miss, forward],
                default_action=on_miss,
            )

            if hdr.ipv4.isValid():
                match ipv4_fib.apply():
                    case "on_miss":
                        ipv4_fib_lpm.apply()

        @p4.deparser
        def MyDeparser(pkt, hdr):
            pkt.emit(hdr.ethernet)
            pkt.emit(hdr.ipv4)

        program = compile(
            V1Switch(parser=MyParser, ingress=MyIngress, deparser=MyDeparser)
        )

        # No exact match entry, but LPM entry matches → forward to port 3.
        table_entries = {
            "ipv4_fib_lpm": [
                {
                    "key": {"hdr.ipv4.dstAddr": 0x0A000000},
                    "prefix_len": {"hdr.ipv4.dstAddr": 8},
                    "action": "forward",
                    "args": {"port": 3},
                },
            ],
        }
        result = simulate(
            program, packet=TEST_PACKET, ingress_port=0, table_entries=table_entries
        )
        assert not result.dropped
        assert result.egress_port == 3

    def test_switch_action_run_hit(self):
        """Switch on action_run skips fallback when action matches."""

        @p4.parser
        def MyParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
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
            def on_miss():
                pass

            @p4.action
            def forward(port: p4.bit(9)):
                std_meta.egress_spec = port

            ipv4_fib = p4.table(
                key={hdr.ipv4.dstAddr: p4.exact},
                actions=[on_miss, forward],
                default_action=on_miss,
            )

            ipv4_fib_lpm = p4.table(
                key={hdr.ipv4.dstAddr: p4.lpm},
                actions=[on_miss, forward],
                default_action=on_miss,
            )

            if hdr.ipv4.isValid():
                match ipv4_fib.apply():
                    case "on_miss":
                        ipv4_fib_lpm.apply()

        @p4.deparser
        def MyDeparser(pkt, hdr):
            pkt.emit(hdr.ethernet)
            pkt.emit(hdr.ipv4)

        program = compile(
            V1Switch(parser=MyParser, ingress=MyIngress, deparser=MyDeparser)
        )

        # Exact match hits → forward to port 5. LPM entry exists but should
        # NOT be used because ipv4_fib matched.
        table_entries = {
            "ipv4_fib": [
                {
                    "key": {"hdr.ipv4.dstAddr": 0x0A000002},
                    "action": "forward",
                    "args": {"port": 5},
                },
            ],
            "ipv4_fib_lpm": [
                {
                    "key": {"hdr.ipv4.dstAddr": 0x0A000000},
                    "prefix_len": {"hdr.ipv4.dstAddr": 8},
                    "action": "forward",
                    "args": {"port": 3},
                },
            ],
        }
        result = simulate(
            program, packet=TEST_PACKET, ingress_port=0, table_entries=table_entries
        )
        assert not result.dropped
        assert result.egress_port == 5

    def test_extract_fails_on_short_packet(self):
        """Extract fails when packet is too short for the header."""
        # 14-byte ethernet with etherType=0x0800, then only 6 bytes of payload
        # (not enough for 20-byte IPv4 header).
        short_packet = (
            b"\x00\x00\x00\x00\x00\x01"  # dstAddr
            b"\x00\x00\x00\x00\x00\x02"  # srcAddr
            b"\x08\x00"  # etherType = IPv4
            b"\x00\x00\x00\x00\x00\x00"  # 6 bytes payload (< 20 needed)
        )
        program = _make_passthrough()
        result = simulate(
            program,
            packet=short_packet,
            ingress_port=0,
            table_entries={},
        )
        # IPv4 extract should fail, so isValid() is false → deparser skips
        # emitting ipv4. Output should be same length as input.
        assert not result.dropped
        assert len(result.packet) == len(short_packet)

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
