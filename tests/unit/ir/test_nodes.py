"""Tests for P4 IR node types."""

from dataclasses import FrozenInstanceError

from absl.testing import absltest

from p4py.ir import nodes


class TestTypes(absltest.TestCase):
    def test_bit_type(self):
        t = nodes.BitType(width=48)
        self.assertEqual(t.width, 48)

    def test_header_type(self):
        h = nodes.HeaderType(
            name="ethernet_t",
            fields=(
                nodes.HeaderField("dstAddr", nodes.BitType(48)),
                nodes.HeaderField("srcAddr", nodes.BitType(48)),
                nodes.HeaderField("etherType", nodes.BitType(16)),
            ),
        )
        self.assertEqual(h.name, "ethernet_t")
        self.assertLen(h.fields, 3)
        self.assertEqual(h.fields[0].name, "dstAddr")
        self.assertEqual(h.fields[0].type.width, 48)

    def test_struct_type(self):
        s = nodes.StructType(
            name="headers_t",
            members=(
                nodes.StructMember("ethernet", "ethernet_t"),
                nodes.StructMember("ipv4", "ipv4_t"),
            ),
        )
        self.assertEqual(s.name, "headers_t")
        self.assertLen(s.members, 2)

    def test_empty_struct(self):
        s = nodes.StructType(name="metadata_t", members=())
        self.assertLen(s.members, 0)


class TestExpressions(absltest.TestCase):
    def test_field_access(self):
        fa = nodes.FieldAccess(path=("hdr", "ethernet", "dstAddr"))
        self.assertEqual(fa.path, ("hdr", "ethernet", "dstAddr"))

    def test_int_literal(self):
        lit = nodes.IntLiteral(value=0x0800)
        self.assertEqual(lit.value, 0x0800)

    def test_arith_op(self):
        expr = nodes.ArithOp(
            op="-",
            left=nodes.FieldAccess(path=("hdr", "ipv4", "ttl")),
            right=nodes.IntLiteral(value=1),
        )
        self.assertEqual(expr.op, "-")

    def test_bool_literal(self):
        t = nodes.BoolLiteral(value=True)
        self.assertTrue(t.value)
        f = nodes.BoolLiteral(value=False)
        self.assertFalse(f.value)

    def test_is_valid(self):
        iv = nodes.IsValid(
            header_ref=nodes.FieldAccess(path=("hdr", "ipv4")),
        )
        self.assertEqual(iv.header_ref.path, ("hdr", "ipv4"))


class TestStatements(absltest.TestCase):
    def test_assignment(self):
        stmt = nodes.Assignment(
            target=nodes.FieldAccess(path=("std_meta", "egress_spec")),
            value=nodes.FieldAccess(path=("port",)),
        )
        self.assertEqual(stmt.target.path, ("std_meta", "egress_spec"))

    def test_method_call(self):
        stmt = nodes.MethodCall(
            object=nodes.FieldAccess(path=("pkt",)),
            method="extract",
            args=(nodes.FieldAccess(path=("hdr", "ethernet")),),
        )
        self.assertEqual(stmt.method, "extract")

    def test_free_function_call(self):
        stmt = nodes.FunctionCall(
            name="mark_to_drop",
            args=(nodes.FieldAccess(path=("std_meta",)),),
        )
        self.assertEqual(stmt.name, "mark_to_drop")

    def test_action_call(self):
        stmt = nodes.ActionCall(name="drop", args=())
        self.assertEqual(stmt.name, "drop")

    def test_table_apply(self):
        stmt = nodes.TableApply(table_name="ipv4_table")
        self.assertEqual(stmt.table_name, "ipv4_table")

    def test_if_else(self):
        stmt = nodes.IfElse(
            condition=nodes.IsValid(
                header_ref=nodes.FieldAccess(path=("hdr", "ipv4")),
            ),
            then_body=(nodes.TableApply(table_name="ipv4_table"),),
            else_body=(nodes.ActionCall(name="drop", args=()),),
        )
        self.assertLen(stmt.then_body, 1)
        self.assertLen(stmt.else_body, 1)


class TestParser(absltest.TestCase):
    def test_transition(self):
        t = nodes.Transition(next_state="parse_ipv4")
        self.assertEqual(t.next_state, "parse_ipv4")

    def test_select_case(self):
        sc = nodes.SelectCase(value=0x0800, next_state="parse_ipv4")
        self.assertEqual(sc.value, 0x0800)

    def test_default_select_case(self):
        sc = nodes.SelectCase(value=None, next_state="accept")
        self.assertIsNone(sc.value)

    def test_transition_select(self):
        ts = nodes.TransitionSelect(
            field=nodes.FieldAccess(path=("hdr", "ethernet", "etherType")),
            cases=(
                nodes.SelectCase(value=0x0800, next_state="parse_ipv4"),
                nodes.SelectCase(value=None, next_state="accept"),
            ),
        )
        self.assertLen(ts.cases, 2)

    def test_parser_state(self):
        state = nodes.ParserState(
            name="start",
            body=(
                nodes.MethodCall(
                    object=nodes.FieldAccess(path=("pkt",)),
                    method="extract",
                    args=(nodes.FieldAccess(path=("hdr", "ethernet")),),
                ),
            ),
            transition=nodes.Transition(next_state="accept"),
        )
        self.assertEqual(state.name, "start")
        self.assertLen(state.body, 1)

    def test_parser_decl(self):
        parser = nodes.ParserDecl(
            name="MyParser",
            states=(
                nodes.ParserState(
                    name="start",
                    body=(),
                    transition=nodes.Transition(next_state="accept"),
                ),
            ),
        )
        self.assertEqual(parser.name, "MyParser")


class TestControl(absltest.TestCase):
    def test_action_param(self):
        p = nodes.ActionParam(name="port", type=nodes.BitType(9))
        self.assertEqual(p.name, "port")

    def test_action_decl(self):
        a = nodes.ActionDecl(name="forward", params=(), body=())
        self.assertEqual(a.name, "forward")

    def test_table_key(self):
        k = nodes.TableKey(
            field=nodes.FieldAccess(path=("hdr", "ipv4", "dstAddr")),
            match_kind="exact",
        )
        self.assertEqual(k.match_kind, "exact")

    def test_table_decl(self):
        t = nodes.TableDecl(
            name="ipv4_table",
            keys=(
                nodes.TableKey(
                    field=nodes.FieldAccess(path=("hdr", "ipv4", "dstAddr")),
                    match_kind="exact",
                ),
            ),
            actions=("forward", "drop"),
            default_action="drop",
            default_action_args=(),
        )
        self.assertEqual(t.name, "ipv4_table")
        self.assertLen(t.keys, 1)

    def test_control_decl(self):
        c = nodes.ControlDecl(
            name="MyIngress",
            actions=(),
            tables=(),
            apply_body=(),
        )
        self.assertEqual(c.name, "MyIngress")


class TestDeparser(absltest.TestCase):
    def test_deparser_decl(self):
        d = nodes.DeparserDecl(
            name="MyDeparser",
            emit_order=(
                nodes.FieldAccess(path=("hdr", "ethernet")),
                nodes.FieldAccess(path=("hdr", "ipv4")),
            ),
        )
        self.assertEqual(d.name, "MyDeparser")
        self.assertLen(d.emit_order, 2)


class TestProgram(absltest.TestCase):
    def test_program(self):
        prog = nodes.Program(
            headers=(),
            structs=(),
            parser=nodes.ParserDecl(name="P", states=()),
            ingress=nodes.ControlDecl(name="I", actions=(), tables=(), apply_body=()),
            deparser=nodes.DeparserDecl(name="D", emit_order=()),
        )
        self.assertEqual(prog.parser.name, "P")
        self.assertEqual(prog.ingress.name, "I")
        self.assertEqual(prog.deparser.name, "D")


class TestNodesFrozen(absltest.TestCase):
    def test_nodes_are_frozen(self):
        t = nodes.BitType(width=8)
        with self.assertRaises(FrozenInstanceError):
            t.width = 16


if __name__ == "__main__":
    absltest.main()
