"""Tests for P4 IR node types."""

from dataclasses import FrozenInstanceError

from p4py.ir import nodes


class TestTypes:
    def test_bit_type(self):
        t = nodes.BitType(width=48)
        assert t.width == 48

    def test_header_type(self):
        h = nodes.HeaderType(
            name="ethernet_t",
            fields=(
                nodes.HeaderField("dstAddr", nodes.BitType(48)),
                nodes.HeaderField("srcAddr", nodes.BitType(48)),
                nodes.HeaderField("etherType", nodes.BitType(16)),
            ),
        )
        assert h.name == "ethernet_t"
        assert len(h.fields) == 3
        assert h.fields[0].name == "dstAddr"
        assert h.fields[0].type.width == 48

    def test_struct_type(self):
        s = nodes.StructType(
            name="headers_t",
            members=(
                nodes.StructMember("ethernet", "ethernet_t"),
                nodes.StructMember("ipv4", "ipv4_t"),
            ),
        )
        assert s.name == "headers_t"
        assert len(s.members) == 2

    def test_empty_struct(self):
        s = nodes.StructType(name="metadata_t", members=())
        assert len(s.members) == 0


class TestExpressions:
    def test_field_access(self):
        fa = nodes.FieldAccess(path=("hdr", "ethernet", "dstAddr"))
        assert fa.path == ("hdr", "ethernet", "dstAddr")

    def test_int_literal(self):
        lit = nodes.IntLiteral(value=0x0800)
        assert lit.value == 0x0800

    def test_arith_op(self):
        expr = nodes.ArithOp(
            op="-",
            left=nodes.FieldAccess(path=("hdr", "ipv4", "ttl")),
            right=nodes.IntLiteral(value=1),
        )
        assert expr.op == "-"

    def test_is_valid(self):
        iv = nodes.IsValid(
            header_ref=nodes.FieldAccess(path=("hdr", "ipv4")),
        )
        assert iv.header_ref.path == ("hdr", "ipv4")


class TestStatements:
    def test_assignment(self):
        stmt = nodes.Assignment(
            target=nodes.FieldAccess(path=("std_meta", "egress_spec")),
            value=nodes.FieldAccess(path=("port",)),
        )
        assert stmt.target.path == ("std_meta", "egress_spec")

    def test_method_call(self):
        stmt = nodes.MethodCall(
            object=nodes.FieldAccess(path=("pkt",)),
            method="extract",
            args=(nodes.FieldAccess(path=("hdr", "ethernet")),),
        )
        assert stmt.method == "extract"

    def test_free_function_call(self):
        stmt = nodes.FunctionCall(
            name="mark_to_drop",
            args=(nodes.FieldAccess(path=("std_meta",)),),
        )
        assert stmt.name == "mark_to_drop"

    def test_action_call(self):
        stmt = nodes.ActionCall(name="drop", args=())
        assert stmt.name == "drop"

    def test_table_apply(self):
        stmt = nodes.TableApply(table_name="ipv4_table")
        assert stmt.table_name == "ipv4_table"

    def test_if_else(self):
        stmt = nodes.IfElse(
            condition=nodes.IsValid(
                header_ref=nodes.FieldAccess(path=("hdr", "ipv4")),
            ),
            then_body=(nodes.TableApply(table_name="ipv4_table"),),
            else_body=(nodes.ActionCall(name="drop", args=()),),
        )
        assert len(stmt.then_body) == 1
        assert len(stmt.else_body) == 1


class TestParser:
    def test_transition(self):
        t = nodes.Transition(next_state="parse_ipv4")
        assert t.next_state == "parse_ipv4"

    def test_select_case(self):
        sc = nodes.SelectCase(value=0x0800, next_state="parse_ipv4")
        assert sc.value == 0x0800

    def test_default_select_case(self):
        sc = nodes.SelectCase(value=None, next_state="accept")
        assert sc.value is None

    def test_transition_select(self):
        ts = nodes.TransitionSelect(
            field=nodes.FieldAccess(path=("hdr", "ethernet", "etherType")),
            cases=(
                nodes.SelectCase(value=0x0800, next_state="parse_ipv4"),
                nodes.SelectCase(value=None, next_state="accept"),
            ),
        )
        assert len(ts.cases) == 2

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
        assert state.name == "start"
        assert len(state.body) == 1

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
        assert parser.name == "MyParser"


class TestControl:
    def test_action_param(self):
        p = nodes.ActionParam(name="port", type=nodes.BitType(9))
        assert p.name == "port"

    def test_action_decl(self):
        a = nodes.ActionDecl(name="forward", params=(), body=())
        assert a.name == "forward"

    def test_table_key(self):
        k = nodes.TableKey(
            field=nodes.FieldAccess(path=("hdr", "ipv4", "dstAddr")),
            match_kind="exact",
        )
        assert k.match_kind == "exact"

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
        assert t.name == "ipv4_table"
        assert len(t.keys) == 1

    def test_control_decl(self):
        c = nodes.ControlDecl(
            name="MyIngress",
            actions=(),
            tables=(),
            apply_body=(),
        )
        assert c.name == "MyIngress"


class TestDeparser:
    def test_deparser_decl(self):
        d = nodes.DeparserDecl(
            name="MyDeparser",
            emit_order=(
                nodes.FieldAccess(path=("hdr", "ethernet")),
                nodes.FieldAccess(path=("hdr", "ipv4")),
            ),
        )
        assert d.name == "MyDeparser"
        assert len(d.emit_order) == 2


class TestProgram:
    def test_program(self):
        prog = nodes.Program(
            headers=(),
            structs=(),
            parser=nodes.ParserDecl(name="P", states=()),
            ingress=nodes.ControlDecl(name="I", actions=(), tables=(), apply_body=()),
            deparser=nodes.DeparserDecl(name="D", emit_order=()),
        )
        assert prog.parser.name == "P"
        assert prog.ingress.name == "I"
        assert prog.deparser.name == "D"


class TestNodesFrozen:
    def test_nodes_are_frozen(self):
        t = nodes.BitType(width=8)
        try:
            t.width = 16
            raise AssertionError("Expected FrozenInstanceError")
        except FrozenInstanceError:
            pass
