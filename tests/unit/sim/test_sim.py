"""Tests for the P4Py simulator."""

from absl.testing import absltest

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


class TestSimulator(absltest.TestCase):
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
        self.assertEqual(result.egress_port, 2)
        self.assertIsNotNone(result.packet)
        # TTL should be decremented from 64 to 63.
        self.assertEqual(result.packet[22], 63)

    def test_drop_on_table_miss(self):
        program = _make_ipv4_forwarder()
        result = simulate(
            program,
            packet=TEST_PACKET,
            ingress_port=1,
            table_entries={},
        )
        self.assertTrue(result.dropped)

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

        # 10.0.0.0/8 -> port 1, 10.0.0.0/24 -> port 2
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
        self.assertFalse(result.dropped)
        self.assertEqual(result.egress_port, 2)

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

        # Entry for 192.168.0.0/16, packet goes to 10.0.0.2 -- no match.
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
        self.assertTrue(result.dropped)

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

            # Exact table -- miss triggers LPM fallback.
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

        # No exact match entry, but LPM entry matches -> forward to port 3.
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
        self.assertFalse(result.dropped)
        self.assertEqual(result.egress_port, 3)

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

        # Exact match hits -> forward to port 5. LPM entry exists but should
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
        self.assertFalse(result.dropped)
        self.assertEqual(result.egress_port, 5)

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
        # IPv4 extract should fail, so isValid() is false -> deparser skips
        # emitting ipv4. Output should be same length as input.
        self.assertFalse(result.dropped)
        self.assertLen(result.packet, len(short_packet))

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
        self.assertTrue(result.dropped)

    def test_nested_metadata_struct(self):
        """Nested metadata struct fields are read/written correctly."""

        class inner_meta_t(p4.struct):
            nexthop_index: p4.bit(16)

        class nested_meta_t(p4.struct):
            ingress_metadata: inner_meta_t

        @p4.parser
        def MyParser(pkt, hdr: headers_t, meta: nested_meta_t, std_meta):
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
            def set_nexthop(idx: p4.bit(16)):
                meta.ingress_metadata.nexthop_index = idx

            @p4.action
            def forward(port: p4.bit(9)):
                std_meta.egress_spec = port

            lookup = p4.table(
                key={meta.ingress_metadata.nexthop_index: p4.exact},
                actions=[forward],
                default_action=forward(0),
            )

            fib = p4.table(
                key={hdr.ipv4.dstAddr: p4.exact},
                actions=[set_nexthop],
                default_action=set_nexthop(0),
            )

            if hdr.ipv4.isValid():
                fib.apply()
                lookup.apply()

        @p4.deparser
        def MyDeparser(pkt, hdr):
            pkt.emit(hdr.ethernet)
            pkt.emit(hdr.ipv4)

        program = compile(
            V1Switch(parser=MyParser, ingress=MyIngress, deparser=MyDeparser)
        )

        table_entries = {
            "fib": [
                {
                    "key": {"hdr.ipv4.dstAddr": 0x0A000002},
                    "action": "set_nexthop",
                    "args": {"idx": 1},
                },
            ],
            "lookup": [
                {
                    "key": {"meta.ingress_metadata.nexthop_index": 1},
                    "action": "forward",
                    "args": {"port": 7},
                },
            ],
        }
        result = simulate(
            program, packet=TEST_PACKET, ingress_port=0, table_entries=table_entries
        )
        self.assertFalse(result.dropped)
        self.assertEqual(result.egress_port, 7)


class TestParserRejectDetection(absltest.TestCase):
    def test_run_parser_returns_accept(self):
        """_run_parser returns 'accept' for a valid packet."""
        from p4py import ir as nodes
        from p4py.sim.engine import (
            _HeaderInstance,
            _run_parser,
            _SimState,
        )

        eth_type = nodes.HeaderType(
            name="ethernet_t",
            fields=(
                nodes.HeaderField("dstAddr", nodes.BitType(48)),
                nodes.HeaderField("srcAddr", nodes.BitType(48)),
                nodes.HeaderField("etherType", nodes.BitType(16)),
            ),
        )
        parser = nodes.ParserDecl(
            name="prs",
            states=(
                nodes.ParserState(
                    name="start",
                    body=(
                        nodes.MethodCall(
                            object=nodes.FieldAccess(("p",)),
                            method="extract",
                            args=(nodes.FieldAccess(("headers", "ethernet")),),
                        ),
                    ),
                    transition=nodes.Transition(next_state="accept"),
                ),
            ),
        )
        state = _SimState(
            packet_bytes=bytearray(b"\x00" * 14),
            cursor=0,
            headers={"ethernet": _HeaderInstance(type_info=eth_type)},
            metadata={},
            metadata_widths={},
            program=None,
        )
        result = _run_parser(state, parser, {})
        self.assertEqual(result, "accept")

    def test_run_parser_returns_accept_on_short_packet(self):
        """_run_parser returns 'accept' even with short packet.

        Header stays invalid when packet is too short.
        """
        from p4py import ir as nodes
        from p4py.sim.engine import _HeaderInstance, _run_parser, _SimState

        eth_type = nodes.HeaderType(
            name="ethernet_t",
            fields=(
                nodes.HeaderField("dstAddr", nodes.BitType(48)),
                nodes.HeaderField("srcAddr", nodes.BitType(48)),
                nodes.HeaderField("etherType", nodes.BitType(16)),
            ),
        )
        parser = nodes.ParserDecl(
            name="prs",
            states=(
                nodes.ParserState(
                    name="start",
                    body=(
                        nodes.MethodCall(
                            object=nodes.FieldAccess(("p",)),
                            method="extract",
                            args=(nodes.FieldAccess(("headers", "ethernet")),),
                        ),
                    ),
                    transition=nodes.Transition(next_state="accept"),
                ),
            ),
        )
        state = _SimState(
            packet_bytes=bytearray(b"\x00" * 5),
            cursor=0,
            headers={"ethernet": _HeaderInstance(type_info=eth_type)},
            metadata={},
            metadata_widths={},
            program=None,
        )
        result = _run_parser(state, parser, {})
        self.assertEqual(result, "accept")


class TestCastAndConstRef(absltest.TestCase):
    def test_eval_cast_truncates(self):
        """Cast evaluation truncates value to target type width."""
        from p4py import ir

        pkg = ir.Package(
            arch=None,
            headers=(),
            structs=(),
            blocks=(),
            declarations=(ir.NewtypeDecl(name="port_id_t", type=ir.BitType(9)),),
        )
        from p4py.sim.engine import _eval_expression, _SimState

        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        # 510 fits in 9 bits
        cast_expr = ir.Cast(type_name="port_id_t", expr=ir.IntLiteral(value=510))
        result = _eval_expression(state, cast_expr, {})
        self.assertEqual(result, 510)

        # 1023 & 0x1FF = 511
        cast_expr2 = ir.Cast(type_name="port_id_t", expr=ir.IntLiteral(value=1023))
        result2 = _eval_expression(state, cast_expr2, {})
        self.assertEqual(result2, 511)

    def test_eval_const_ref(self):
        """ConstRef evaluation resolves to the declared constant value."""
        from p4py import ir

        pkg = ir.Package(
            arch=None,
            headers=(),
            structs=(),
            blocks=(),
            declarations=(
                ir.ConstDecl(name="MY_CONST", type_name="bit<16>", value=42),
            ),
        )
        from p4py.sim.engine import _eval_expression, _SimState

        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        ref_expr = ir.ConstRef(name="MY_CONST")
        result = _eval_expression(state, ref_expr, {})
        self.assertEqual(result, 42)

    def test_eval_unary_not_true(self):
        """UnaryOp('!') on truthy value returns 0."""
        from p4py import ir
        from p4py.sim.engine import _eval_expression, _SimState

        pkg = ir.Package(arch=None, headers=(), structs=(), blocks=(), declarations=())
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        expr = ir.UnaryOp(op="!", operand=ir.IntLiteral(value=1))
        self.assertEqual(_eval_expression(state, expr, {}), 0)

    def test_eval_unary_not_false(self):
        """UnaryOp('!') on falsy value returns 1."""
        from p4py import ir
        from p4py.sim.engine import _eval_expression, _SimState

        pkg = ir.Package(arch=None, headers=(), structs=(), blocks=(), declarations=())
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        expr = ir.UnaryOp(op="!", operand=ir.IntLiteral(value=0))
        self.assertEqual(_eval_expression(state, expr, {}), 1)

    def test_eval_compare_eq(self):
        """CompareOp('==') returns 1 when equal, 0 otherwise."""
        from p4py import ir
        from p4py.sim.engine import _eval_expression, _SimState

        pkg = ir.Package(arch=None, headers=(), structs=(), blocks=(), declarations=())
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        eq_true = ir.CompareOp(
            op="==", left=ir.IntLiteral(value=5), right=ir.IntLiteral(value=5)
        )
        self.assertEqual(_eval_expression(state, eq_true, {}), 1)
        eq_false = ir.CompareOp(
            op="==", left=ir.IntLiteral(value=5), right=ir.IntLiteral(value=3)
        )
        self.assertEqual(_eval_expression(state, eq_false, {}), 0)

    def test_eval_compare_neq(self):
        """CompareOp('!=') returns 1 when not equal, 0 otherwise."""
        from p4py import ir
        from p4py.sim.engine import _eval_expression, _SimState

        pkg = ir.Package(arch=None, headers=(), structs=(), blocks=(), declarations=())
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        neq_true = ir.CompareOp(
            op="!=", left=ir.IntLiteral(value=5), right=ir.IntLiteral(value=3)
        )
        self.assertEqual(_eval_expression(state, neq_true, {}), 1)
        neq_false = ir.CompareOp(
            op="!=", left=ir.IntLiteral(value=5), right=ir.IntLiteral(value=5)
        )
        self.assertEqual(_eval_expression(state, neq_false, {}), 0)

    def test_eval_logical_and(self):
        """LogicalOp('&&') short-circuits correctly."""
        from p4py import ir
        from p4py.sim.engine import _eval_expression, _SimState

        pkg = ir.Package(arch=None, headers=(), structs=(), blocks=(), declarations=())
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        both_true = ir.LogicalOp(
            op="&&", left=ir.IntLiteral(value=1), right=ir.IntLiteral(value=1)
        )
        self.assertEqual(_eval_expression(state, both_true, {}), 1)
        left_false = ir.LogicalOp(
            op="&&", left=ir.IntLiteral(value=0), right=ir.IntLiteral(value=1)
        )
        self.assertEqual(_eval_expression(state, left_false, {}), 0)

    def test_eval_logical_or(self):
        """LogicalOp('||') short-circuits correctly."""
        from p4py import ir
        from p4py.sim.engine import _eval_expression, _SimState

        pkg = ir.Package(arch=None, headers=(), structs=(), blocks=(), declarations=())
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        left_true = ir.LogicalOp(
            op="||", left=ir.IntLiteral(value=1), right=ir.IntLiteral(value=0)
        )
        self.assertEqual(_eval_expression(state, left_true, {}), 1)
        both_false = ir.LogicalOp(
            op="||", left=ir.IntLiteral(value=0), right=ir.IntLiteral(value=0)
        )
        self.assertEqual(_eval_expression(state, both_false, {}), 0)

    def test_eval_bitwise_and(self):
        """ArithOp('&') computes bitwise AND."""
        from p4py import ir
        from p4py.sim.engine import _eval_expression, _SimState

        pkg = ir.Package(arch=None, headers=(), structs=(), blocks=(), declarations=())
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        expr = ir.ArithOp(
            op="&",
            left=ir.IntLiteral(value=0xFF00),
            right=ir.IntLiteral(value=0x0F0F),
        )
        self.assertEqual(_eval_expression(state, expr, {}), 0x0F00)

    def test_eval_bitwise_and_with_compare(self):
        """(x & mask) == 0 evaluates correctly."""
        from p4py import ir
        from p4py.sim.engine import _eval_expression, _SimState

        pkg = ir.Package(arch=None, headers=(), structs=(), blocks=(), declarations=())
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        # 0x00AABB & 0x010000 == 0 -> True (multicast bit not set)
        expr = ir.CompareOp(
            op="==",
            left=ir.ArithOp(
                op="&",
                left=ir.IntLiteral(value=0x00AABB),
                right=ir.IntLiteral(value=0x010000),
            ),
            right=ir.IntLiteral(value=0),
        )
        self.assertEqual(_eval_expression(state, expr, {}), 1)

        # 0x01AABB & 0x010000 == 0 -> False (multicast bit set)
        expr2 = ir.CompareOp(
            op="==",
            left=ir.ArithOp(
                op="&",
                left=ir.IntLiteral(value=0x01AABB),
                right=ir.IntLiteral(value=0x010000),
            ),
            right=ir.IntLiteral(value=0),
        )
        self.assertEqual(_eval_expression(state, expr2, {}), 0)

    def test_const_ref_unknown_raises(self):
        """ConstRef for unknown constant raises ValueError."""
        from p4py import ir

        pkg = ir.Package(
            arch=None,
            headers=(),
            structs=(),
            blocks=(),
            declarations=(),
        )
        from p4py.sim.engine import _eval_expression, _SimState

        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        ref_expr = ir.ConstRef(name="MISSING")
        with self.assertRaises(ValueError):
            _eval_expression(state, ref_expr, {})

    def test_select_with_const_ref(self):
        """Parser select matches ConstRef case values."""
        from p4py import ir
        from p4py.sim.engine import _match_select, _SimState

        pkg = ir.Package(
            arch=None,
            headers=(),
            structs=(),
            blocks=(),
            declarations=(
                ir.ConstDecl(name="ETHERTYPE_IPV4", type_name="bit<16>", value=0x0800),
            ),
        )
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={},
            metadata={},
            metadata_widths={},
            program=pkg,
        )
        cases = (
            ir.SelectCase(
                value=ir.ConstRef(name="ETHERTYPE_IPV4"), next_state="parse_ipv4"
            ),
            ir.SelectCase(value=None, next_state="accept"),
        )
        self.assertEqual(_match_select(state, cases, 0x0800), "parse_ipv4")
        self.assertEqual(_match_select(state, cases, 0x0806), "accept")


class TestSetValidInvalid(absltest.TestCase):
    def test_set_valid(self):
        """setValid() marks a header as valid."""
        from p4py import ir
        from p4py.sim.engine import _exec_statement, _HeaderInstance, _SimState

        eth_type = ir.HeaderType(
            name="ethernet_t",
            fields=(ir.HeaderField("dstAddr", ir.BitType(48)),),
        )
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={"ethernet": _HeaderInstance(type_info=eth_type, valid=False)},
            metadata={},
            metadata_widths={},
            program=None,
        )
        stmt = ir.MethodCall(
            object=ir.FieldAccess(path=("hdr", "ethernet")),
            method="setValid",
            args=(),
        )
        _exec_statement(state, stmt, {}, {})
        self.assertTrue(state.headers["ethernet"].valid)

    def test_set_invalid(self):
        """setInvalid() marks a header as invalid."""
        from p4py import ir
        from p4py.sim.engine import _exec_statement, _HeaderInstance, _SimState

        eth_type = ir.HeaderType(
            name="ethernet_t",
            fields=(ir.HeaderField("dstAddr", ir.BitType(48)),),
        )
        state = _SimState(
            packet_bytes=bytearray(),
            cursor=0,
            headers={"ethernet": _HeaderInstance(type_info=eth_type, valid=True)},
            metadata={},
            metadata_widths={},
            program=None,
        )
        stmt = ir.MethodCall(
            object=ir.FieldAccess(path=("hdr", "ethernet")),
            method="setInvalid",
            args=(),
        )
        _exec_statement(state, stmt, {}, {})
        self.assertFalse(state.headers["ethernet"].valid)


if __name__ == "__main__":
    absltest.main()
