"""Tests for the P4Mini compiler."""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch import ebpf_model
from p4py.arch.v1model import V1Switch, mark_to_drop
from p4py.compiler import compile
from p4py.ir import nodes


# Shared type fixtures.
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


class TestCompileParser(absltest.TestCase):
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
        self.assertEqual(parser_ir.name, "MyParser")
        self.assertLen(parser_ir.states, 1)

        start = parser_ir.states[0]
        self.assertEqual(start.name, "start")
        self.assertLen(start.body, 1)
        self.assertIsInstance(start.body[0], nodes.MethodCall)
        self.assertEqual(start.body[0].method, "extract")
        self.assertIsInstance(start.transition, nodes.Transition)
        self.assertEqual(start.transition.next_state, "accept")

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
        self.assertLen(parser_ir.states, 2)

        start = parser_ir.states[0]
        self.assertIsInstance(start.transition, nodes.TransitionSelect)
        self.assertEqual(
            start.transition.field,
            nodes.FieldAccess(path=("hdr", "ethernet", "etherType")),
        )
        self.assertLen(start.transition.cases, 2)
        self.assertEqual(
            start.transition.cases[0],
            nodes.SelectCase(value=0x0800, next_state="parse_ipv4"),
        )
        self.assertEqual(
            start.transition.cases[1],
            nodes.SelectCase(value=None, next_state="accept"),
        )

        parse_ipv4 = parser_ir.states[1]
        self.assertEqual(parse_ipv4.name, "parse_ipv4")
        self.assertIsInstance(parse_ipv4.transition, nodes.Transition)


class TestCompileControl(absltest.TestCase):
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
        self.assertEqual(ingress.name, "MyIngress")

        # Actions
        self.assertLen(ingress.actions, 2)
        fwd = ingress.actions[0]
        self.assertEqual(fwd.name, "forward")
        self.assertLen(fwd.params, 1)
        self.assertEqual(fwd.params[0], nodes.ActionParam("port", nodes.BitType(9)))
        self.assertLen(fwd.body, 1)
        self.assertIsInstance(fwd.body[0], nodes.Assignment)

        drop_action = ingress.actions[1]
        self.assertEqual(drop_action.name, "drop")
        self.assertLen(drop_action.params, 0)
        self.assertIsInstance(drop_action.body[0], nodes.FunctionCall)
        self.assertEqual(drop_action.body[0].name, "mark_to_drop")

        # Table
        self.assertLen(ingress.tables, 1)
        tbl = ingress.tables[0]
        self.assertEqual(tbl.name, "ipv4_table")
        self.assertEqual(tbl.keys[0].match_kind, "exact")
        self.assertEqual(
            tbl.keys[0].field, nodes.FieldAccess(path=("hdr", "ipv4", "dstAddr"))
        )
        self.assertEqual(tbl.actions, ("forward", "drop"))
        self.assertEqual(tbl.default_action, "drop")

        # Apply body
        self.assertLen(ingress.apply_body, 1)
        if_else = ingress.apply_body[0]
        self.assertIsInstance(if_else, nodes.IfElse)
        self.assertIsInstance(if_else.condition, nodes.IsValid)
        self.assertEqual(
            if_else.condition.header_ref, nodes.FieldAccess(path=("hdr", "ipv4"))
        )
        self.assertIsInstance(if_else.then_body[0], nodes.TableApply)
        self.assertIsInstance(if_else.else_body[0], nodes.FunctionCall)

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
        self.assertIsInstance(drop_action.body[0], nodes.FunctionCall)
        self.assertEqual(drop_action.body[0].name, "mark_to_drop")


class TestCompileDeparser(absltest.TestCase):
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
        self.assertEqual(dep.name, "MyDeparser")
        self.assertLen(dep.emit_order, 2)
        self.assertEqual(dep.emit_order[0], nodes.FieldAccess(path=("hdr", "ethernet")))
        self.assertEqual(dep.emit_order[1], nodes.FieldAccess(path=("hdr", "ipv4")))


class TestCompileProgram(absltest.TestCase):
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
        self.assertLen(program.headers, 2)
        self.assertEqual(program.headers[0].name, "ethernet_t")
        self.assertEqual(program.headers[1].name, "ipv4_t")
        self.assertLen(program.headers[0].fields, 3)
        self.assertEqual(
            program.headers[0].fields[0],
            nodes.HeaderField("dstAddr", nodes.BitType(48)),
        )

        # Structs
        self.assertLen(program.structs, 2)
        self.assertEqual(program.structs[0].name, "headers_t")
        self.assertEqual(program.structs[1].name, "metadata_t")
        self.assertEqual(
            program.structs[0].members[0], nodes.StructMember("ethernet", "ethernet_t")
        )

    def test_nested_struct_compiled(self):
        class ingress_metadata_t(p4.struct):
            vrf: p4.bit(12)
            bd: p4.bit(16)

        class nested_meta_t(p4.struct):
            ingress_metadata: ingress_metadata_t

        @p4.parser
        def P(pkt, hdr: headers_t, meta: nested_meta_t, std_meta):
            def start():
                return p4.ACCEPT

        @p4.control
        def I(hdr, meta, std_meta):
            pass

        @p4.deparser
        def D(pkt, hdr):
            pass

        pipeline = V1Switch(parser=P, ingress=I, deparser=D)
        program = compile(pipeline)

        # Inner struct should appear before outer struct.
        struct_names = [s.name for s in program.structs]
        self.assertIn("ingress_metadata_t", struct_names)
        self.assertIn("nested_meta_t", struct_names)
        self.assertLess(
            struct_names.index("ingress_metadata_t"),
            struct_names.index("nested_meta_t"),
        )

        # Outer struct should reference inner by name.
        outer = next(s for s in program.structs if s.name == "nested_meta_t")
        self.assertLen(outer.members, 1)
        self.assertEqual(
            outer.members[0],
            nodes.StructMember("ingress_metadata", "ingress_metadata_t"),
        )

        # Inner struct should have bit fields.
        inner = next(s for s in program.structs if s.name == "ingress_metadata_t")
        self.assertLen(inner.members, 2)
        self.assertEqual(inner.members[0], nodes.StructMember("vrf", nodes.BitType(12)))


class TestCompileEbpf(absltest.TestCase):
    def test_compile_init_ebpf(self):
        """Compile a minimal eBPF program to IR."""

        class Ethernet(p4.header):
            destination: p4.bit(48)
            source: p4.bit(48)
            protocol: p4.bit(16)

        class Headers_t(p4.struct):
            ethernet: Ethernet

        @p4.parser
        def prs(p, headers: Headers_t):
            def start():
                p.extract(headers.ethernet)
                return p4.ACCEPT

        @p4.control
        def pipe(headers: Headers_t, pass_):
            @p4.action
            def match(act: p4.bool):
                pass_ = act

            tbl = p4.table(
                key={headers.ethernet.protocol: p4.exact},
                actions=[match, p4.NoAction],
                const_entries={
                    p4.hex(0x0800): match(True),
                    p4.hex(0xD000): match(False),
                },
                implementation=ebpf_model.hash_table(64),
            )

            pass_ = True
            tbl.apply()

        pipeline = ebpf_model.ebpfFilter(parser=prs, filter=pipe)
        program = compile(pipeline)

        self.assertIsInstance(program, nodes.EbpfProgram)
        self.assertEqual(program.parser.name, "prs")
        self.assertEqual(program.filter.name, "pipe")
        self.assertEqual(len(program.headers), 1)
        self.assertEqual(program.headers[0].name, "Ethernet")

        # Check table has const_entries and implementation.
        self.assertEqual(len(program.filter.tables), 1)
        tbl = program.filter.tables[0]
        self.assertEqual(tbl.name, "tbl")
        self.assertEqual(len(tbl.const_entries), 2)
        self.assertEqual(tbl.implementation, "hash_table(64)")

        # Check bool param on action.
        match_action = program.filter.actions[0]
        self.assertEqual(match_action.name, "match")
        self.assertIsInstance(match_action.params[0].type, nodes.BoolType)


if __name__ == "__main__":
    absltest.main()
