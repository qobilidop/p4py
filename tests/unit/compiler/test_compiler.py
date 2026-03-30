"""Tests for the P4Py compiler."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch import ebpf_model
from p4py.arch.v1model import V1Switch, mark_to_drop
from p4py.compiler import compile


def _get_block(package, name):
    """Get a block declaration from a Package by name."""
    for entry in package.blocks:
        if entry.name == name:
            return entry.decl
    return None


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
        package = compile(pipeline)

        parser_ir = _get_block(package, "parser")
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
        package = compile(pipeline)

        parser_ir = _get_block(package, "parser")
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
        package = compile(pipeline)

        ingress = _get_block(package, "ingress")
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
        package = compile(pipeline)

        ingress = _get_block(package, "ingress")
        drop_action = ingress.actions[0]
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
        package = compile(pipeline)

        dep = _get_block(package, "deparser")
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
        package = compile(pipeline)

        # Headers extracted from struct
        self.assertLen(package.headers, 2)
        self.assertEqual(package.headers[0].name, "ethernet_t")
        self.assertEqual(package.headers[1].name, "ipv4_t")
        self.assertLen(package.headers[0].fields, 3)
        self.assertEqual(
            package.headers[0].fields[0],
            nodes.HeaderField("dstAddr", nodes.BitType(48)),
        )

        # Structs
        self.assertLen(package.structs, 2)
        self.assertEqual(package.structs[0].name, "headers_t")
        self.assertEqual(package.structs[1].name, "metadata_t")
        self.assertEqual(
            package.structs[0].members[0], nodes.StructMember("ethernet", "ethernet_t")
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
        package = compile(pipeline)

        # Inner struct should appear before outer struct.
        struct_names = [s.name for s in package.structs]
        self.assertIn("ingress_metadata_t", struct_names)
        self.assertIn("nested_meta_t", struct_names)
        self.assertLess(
            struct_names.index("ingress_metadata_t"),
            struct_names.index("nested_meta_t"),
        )

        # Outer struct should reference inner by name.
        outer = next(s for s in package.structs if s.name == "nested_meta_t")
        self.assertLen(outer.members, 1)
        self.assertEqual(
            outer.members[0],
            nodes.StructMember("ingress_metadata", "ingress_metadata_t"),
        )

        # Inner struct should have bit fields.
        inner = next(s for s in package.structs if s.name == "ingress_metadata_t")
        self.assertLen(inner.members, 2)
        self.assertEqual(inner.members[0], nodes.StructMember("vrf", nodes.BitType(12)))


class TestCompileCast(absltest.TestCase):
    def test_compile_cast_in_parser(self):
        """Cast expression in parser state compiles to Cast IR."""
        port_id_t = p4.newtype(p4.bit(9), "port_id_t")

        class h_t(p4.header):
            f: p4.bit(8)

        class _headers_t(p4.struct):
            h: h_t

        class _meta_t(p4.struct):
            ingress_port: port_id_t

        @p4.parser
        def MyParser(pkt, hdr: _headers_t, meta: _meta_t, std_meta):
            def start():
                meta.ingress_port = p4.cast(port_id_t, std_meta.ingress_port)
                return p4.ACCEPT

        main = V1Switch(
            parser=MyParser,
            verify_checksum=None,
            ingress=None,
            egress=None,
            compute_checksum=None,
            deparser=None,
        )
        pkg = compile(main)
        parser_decl = pkg.blocks[0].decl
        start_state = parser_decl.states[0]
        self.assertLen(start_state.body, 1)
        assign = start_state.body[0]
        self.assertIsInstance(assign, nodes.Assignment)
        self.assertIsInstance(assign.value, nodes.Cast)
        self.assertEqual(assign.value.type_name, "port_id_t")


class _Consts:
    """Namespace for constants used in match/case (Python requires dotted names)."""

    ETHERTYPE_IPV4 = p4.const(
        p4.typedef(p4.bit(16), "bit16_t"), 0x0800, "ETHERTYPE_IPV4"
    )


class TestCompileConstRef(absltest.TestCase):
    def test_compile_const_ref_in_select(self):
        """Named constants in select cases compile to ConstRef."""

        class h_t(p4.header):
            f: p4.bit(16)

        class _headers_t(p4.struct):
            h: h_t

        class _meta_t(p4.struct):
            pass

        @p4.parser
        def MyParser(pkt, hdr: _headers_t, meta: _meta_t, std_meta):
            def start():
                pkt.extract(hdr.h)
                match hdr.h.f:
                    case _Consts.ETHERTYPE_IPV4:
                        return p4.ACCEPT
                    case _:
                        return p4.REJECT

        main = V1Switch(
            parser=MyParser,
            verify_checksum=None,
            ingress=None,
            egress=None,
            compute_checksum=None,
            deparser=None,
        )
        pkg = compile(main)
        parser_decl = pkg.blocks[0].decl
        ts = parser_decl.states[0].transition
        self.assertIsInstance(ts, nodes.TransitionSelect)
        self.assertIsInstance(ts.cases[0].value, nodes.ConstRef)
        self.assertEqual(ts.cases[0].value.name, "ETHERTYPE_IPV4")


class TestCompileExpressions(absltest.TestCase):
    def test_compile_not(self):
        """not expr compiles to UnaryOp('!')."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            if not hdr.ipv4.isValid():
                pass

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")
        if_else = ingress.apply_body[0]
        self.assertIsInstance(if_else.condition, nodes.UnaryOp)
        self.assertEqual(if_else.condition.op, "!")
        self.assertIsInstance(if_else.condition.operand, nodes.IsValid)

    def test_compile_compare_eq(self):
        """== compiles to CompareOp('==')."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            if hdr.ethernet.etherType == 0x0800:
                pass

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")
        if_else = ingress.apply_body[0]
        self.assertIsInstance(if_else.condition, nodes.CompareOp)
        self.assertEqual(if_else.condition.op, "==")
        self.assertIsInstance(if_else.condition.left, nodes.FieldAccess)
        self.assertIsInstance(if_else.condition.right, nodes.IntLiteral)
        self.assertEqual(if_else.condition.right.value, 0x0800)

    def test_compile_compare_neq(self):
        """!= compiles to CompareOp('!=')."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            if hdr.ethernet.etherType != 0x0800:
                pass

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")
        if_else = ingress.apply_body[0]
        self.assertIsInstance(if_else.condition, nodes.CompareOp)
        self.assertEqual(if_else.condition.op, "!=")

    def test_compile_logical_and(self):
        """and compiles to LogicalOp('&&')."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            if hdr.ipv4.isValid() and hdr.ethernet.isValid():
                pass

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")
        if_else = ingress.apply_body[0]
        self.assertIsInstance(if_else.condition, nodes.LogicalOp)
        self.assertEqual(if_else.condition.op, "&&")
        self.assertIsInstance(if_else.condition.left, nodes.IsValid)
        self.assertIsInstance(if_else.condition.right, nodes.IsValid)

    def test_compile_logical_or(self):
        """or compiles to LogicalOp('||')."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            if hdr.ipv4.isValid() or hdr.ethernet.isValid():
                pass

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")
        if_else = ingress.apply_body[0]
        self.assertIsInstance(if_else.condition, nodes.LogicalOp)
        self.assertEqual(if_else.condition.op, "||")

    def test_compile_chained_and(self):
        """a and b and c folds to nested LogicalOp."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            if hdr.ipv4.isValid() and hdr.ethernet.isValid() and hdr.ipv4.ttl == 64:
                pass

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")
        if_else = ingress.apply_body[0]
        # (a && b) && c
        self.assertIsInstance(if_else.condition, nodes.LogicalOp)
        self.assertEqual(if_else.condition.op, "&&")
        self.assertIsInstance(if_else.condition.left, nodes.LogicalOp)
        self.assertIsInstance(if_else.condition.right, nodes.CompareOp)


    def test_compile_bitwise_and(self):
        """& compiles to ArithOp('&')."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            meta.flag = (hdr.ethernet.dstAddr & p4.hex(0x010000000000)) == 0

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)

        ingress = _get_block(package, "ingress")
        assign = ingress.apply_body[0]
        self.assertIsInstance(assign, nodes.Assignment)
        cmp = assign.value
        self.assertIsInstance(cmp, nodes.CompareOp)
        self.assertEqual(cmp.op, "==")
        self.assertIsInstance(cmp.left, nodes.ArithOp)
        self.assertEqual(cmp.left.op, "&")
        self.assertIsInstance(cmp.left.left, nodes.FieldAccess)
        self.assertIsInstance(cmp.left.right, nodes.IntLiteral)
        self.assertTrue(cmp.left.right.hex)
        self.assertEqual(cmp.left.right.value, 0x010000000000)
        self.assertEqual(cmp.right.value, 0)


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
                pass_ = act  # noqa: F841

            tbl = p4.table(
                key={headers.ethernet.protocol: p4.exact},
                actions=[match, p4.NoAction],
                const_entries={
                    p4.hex(0x0800): match(True),
                    p4.hex(0xD000): match(False),
                },
                implementation=ebpf_model.hash_table(64),
            )

            pass_ = True  # noqa: F841
            tbl.apply()

        pipeline = ebpf_model.ebpfFilter(parser=prs, filter=pipe)
        package = compile(pipeline)

        self.assertIsInstance(package, nodes.Package)
        parser_ir = _get_block(package, "parser")
        filter_ir = _get_block(package, "filter")
        self.assertEqual(parser_ir.name, "prs")
        self.assertEqual(filter_ir.name, "pipe")
        self.assertEqual(len(package.headers), 1)
        self.assertEqual(package.headers[0].name, "Ethernet")

        # Check table has const_entries and implementation.
        self.assertEqual(len(filter_ir.tables), 1)
        tbl = filter_ir.tables[0]
        self.assertEqual(tbl.name, "tbl")
        self.assertEqual(len(tbl.const_entries), 2)
        self.assertEqual(tbl.implementation, "hash_table(64)")

        # Check bool param on action.
        match_action = filter_ir.actions[0]
        self.assertEqual(match_action.name, "match")
        self.assertIsInstance(match_action.params[0].type, nodes.BoolType)


if __name__ == "__main__":
    absltest.main()
