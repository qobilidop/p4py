"""Tests for the P4Mini compiler."""

import p4py.lang as p4
from p4py.arch.v1model import V1Switch, mark_to_drop
from p4py.compiler import compile
from p4py.ir import nodes
from p4py.lang.bit import bit
from p4py.lang.header import header
from p4py.lang.struct import struct


# Shared type fixtures.
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


def _dummy_parser():
    @p4.parser
    def P(pkt, hdr: headers_t, meta: metadata_t, std_meta):
        def start():
            return p4.ACCEPT

    return P


def _dummy_ingress():
    @p4.control
    def I(hdr, meta, std_meta):
        pass

    return I


def _dummy_deparser():
    @p4.deparser
    def D(pkt, hdr):
        pass

    return D


class TestCompileParser:
    def test_simple_parser_with_transition(self):
        @p4.parser
        def MyParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
            def start():
                pkt.extract(hdr.ethernet)
                return p4.ACCEPT

        pipeline = V1Switch(
            parser=MyParser,
            ingress=_dummy_ingress(),
            deparser=_dummy_deparser(),
        )
        program = compile(pipeline)

        parser_ir = program.parser
        assert parser_ir.name == "MyParser"
        assert len(parser_ir.states) == 1

        start = parser_ir.states[0]
        assert start.name == "start"
        assert len(start.body) == 1
        assert isinstance(start.body[0], nodes.MethodCall)
        assert start.body[0].method == "extract"
        assert isinstance(start.transition, nodes.Transition)
        assert start.transition.next_state == "accept"

    def test_parser_with_transition_select(self):
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

        pipeline = V1Switch(
            parser=MyParser,
            ingress=_dummy_ingress(),
            deparser=_dummy_deparser(),
        )
        program = compile(pipeline)

        parser_ir = program.parser
        assert len(parser_ir.states) == 2

        start = parser_ir.states[0]
        assert isinstance(start.transition, nodes.TransitionSelect)
        assert start.transition.field == nodes.FieldAccess(
            path=("hdr", "ethernet", "etherType")
        )
        assert len(start.transition.cases) == 2
        assert start.transition.cases[0] == nodes.SelectCase(
            value=0x0800, next_state="parse_ipv4"
        )
        assert start.transition.cases[1] == nodes.SelectCase(
            value=None, next_state="accept"
        )

        parse_ipv4 = parser_ir.states[1]
        assert parse_ipv4.name == "parse_ipv4"
        assert isinstance(parse_ipv4.transition, nodes.Transition)


class TestCompileControl:
    def test_action_with_params(self):
        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def forward(port: p4.bit(9)):
                std_meta.egress_spec = port

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

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        program = compile(pipeline)

        ingress = program.ingress
        assert ingress.name == "MyIngress"

        # Actions
        assert len(ingress.actions) == 2
        fwd = ingress.actions[0]
        assert fwd.name == "forward"
        assert len(fwd.params) == 1
        assert fwd.params[0] == nodes.ActionParam("port", nodes.BitType(9))
        assert len(fwd.body) == 1
        assert isinstance(fwd.body[0], nodes.Assignment)

        drop_action = ingress.actions[1]
        assert drop_action.name == "drop"
        assert len(drop_action.params) == 0
        assert isinstance(drop_action.body[0], nodes.FunctionCall)
        assert drop_action.body[0].name == "mark_to_drop"

        # Table
        assert len(ingress.tables) == 1
        tbl = ingress.tables[0]
        assert tbl.name == "ipv4_table"
        assert tbl.keys[0].match_kind == "exact"
        assert tbl.keys[0].field == nodes.FieldAccess(path=("hdr", "ipv4", "dstAddr"))
        assert tbl.actions == ("forward", "drop")
        assert tbl.default_action == "drop"

        # Apply body
        assert len(ingress.apply_body) == 1
        if_else = ingress.apply_body[0]
        assert isinstance(if_else, nodes.IfElse)
        assert isinstance(if_else.condition, nodes.IsValid)
        assert if_else.condition.header_ref == nodes.FieldAccess(path=("hdr", "ipv4"))
        assert isinstance(if_else.then_body[0], nodes.TableApply)
        assert isinstance(if_else.else_body[0], nodes.FunctionCall)


    def test_module_qualified_extern(self):
        """v1model.mark_to_drop(std_meta) compiles to FunctionCall."""
        from p4py.arch import v1model

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def drop():
                v1model.mark_to_drop(std_meta)

            drop()

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        program = compile(pipeline)

        drop_action = program.ingress.actions[0]
        assert isinstance(drop_action.body[0], nodes.FunctionCall)
        assert drop_action.body[0].name == "mark_to_drop"


class TestCompileDeparser:
    def test_emit_order(self):
        @p4.deparser
        def MyDeparser(pkt, hdr):
            pkt.emit(hdr.ethernet)
            pkt.emit(hdr.ipv4)

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=_dummy_ingress(),
            deparser=MyDeparser,
        )
        program = compile(pipeline)

        dep = program.deparser
        assert dep.name == "MyDeparser"
        assert len(dep.emit_order) == 2
        assert dep.emit_order[0] == nodes.FieldAccess(path=("hdr", "ethernet"))
        assert dep.emit_order[1] == nodes.FieldAccess(path=("hdr", "ipv4"))


class TestCompileProgram:
    def test_full_program_types(self):
        @p4.parser
        def P(pkt, hdr: headers_t, meta: metadata_t, std_meta):
            def start():
                return p4.ACCEPT

        @p4.control
        def I(hdr, meta, std_meta):
            pass

        @p4.deparser
        def D(pkt, hdr):
            pass

        pipeline = V1Switch(
            parser=P,
            ingress=I,
            deparser=D,
        )
        program = compile(pipeline)

        # Headers extracted from struct
        assert len(program.headers) == 2
        assert program.headers[0].name == "ethernet_t"
        assert program.headers[1].name == "ipv4_t"
        assert len(program.headers[0].fields) == 3
        assert program.headers[0].fields[0] == nodes.HeaderField(
            "dstAddr", nodes.BitType(48)
        )

        # Structs
        assert len(program.structs) == 2
        assert program.structs[0].name == "headers_t"
        assert program.structs[1].name == "metadata_t"
        assert program.structs[0].members[0] == nodes.StructMember(
            "ethernet", "ethernet_t"
        )
