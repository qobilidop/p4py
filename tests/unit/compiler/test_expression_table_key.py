"""Tests for expression-based table keys."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch.v1model import V1Switch
from p4py.compiler import compile
from p4py.emitter.p4 import _emit_table

# --- Type fixtures ---


class ipv4_t(p4.header):
    version: p4.bit(4)
    srcAddr: p4.bit(32)
    dstAddr: p4.bit(32)


class ipv6_t(p4.header):
    version: p4.bit(4)
    srcAddr: p4.bit(128)
    dstAddr: p4.bit(128)


class ethernet_t(p4.header):
    dstAddr: p4.bit(48)
    srcAddr: p4.bit(48)
    etherType: p4.bit(16)


class headers_t(p4.struct):
    ethernet: ethernet_t
    ipv4: ipv4_t
    ipv6: ipv6_t


class metadata_t(p4.struct):
    pass


def _get_block(package, name):
    for entry in package.blocks:
        if entry.name == name:
            return entry.decl
    return None


def _dummy_parser():
    @p4.parser
    def P(pkt, hdr: headers_t, meta: metadata_t, std_meta):
        def start():
            return p4.ACCEPT

    return P


def _dummy_deparser():
    @p4.deparser
    def D(pkt, hdr):
        pass

    return D


class TestExpressionTableKey(absltest.TestCase):
    """Test that logical-or expression table keys compile and emit correctly."""

    def test_compile_logical_or_key(self):
        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def nop():
                pass

            my_table = p4.table(
                key={
                    hdr.ipv4.isValid() or hdr.ipv6.isValid(): p4.optional,
                    hdr.ethernet.etherType: p4.ternary,
                },
                actions=[nop, p4.NoAction],
                default_action=p4.NoAction,
            )

            my_table.apply()

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)

        ingress = _get_block(package, "ingress")
        self.assertLen(ingress.tables, 1)
        tbl = ingress.tables[0]
        self.assertLen(tbl.keys, 2)

        # First key: LogicalOp of two IsValid
        key0 = tbl.keys[0]
        self.assertIsInstance(key0.field, nodes.LogicalOp)
        self.assertEqual(key0.field.op, "||")
        self.assertIsInstance(key0.field.left, nodes.IsValid)
        self.assertIsInstance(key0.field.right, nodes.IsValid)
        self.assertEqual(key0.match_kind, "optional")

        # Second key: plain field access
        key1 = tbl.keys[1]
        self.assertIsInstance(key1.field, nodes.FieldAccess)
        self.assertEqual(key1.match_kind, "ternary")

    def test_emit_logical_or_key(self):
        tbl = nodes.TableDecl(
            name="my_table",
            keys=(
                nodes.TableKey(
                    field=nodes.LogicalOp(
                        op="||",
                        left=nodes.IsValid(
                            header_ref=nodes.FieldAccess(path=("headers", "ipv4"))
                        ),
                        right=nodes.IsValid(
                            header_ref=nodes.FieldAccess(path=("headers", "ipv6"))
                        ),
                    ),
                    match_kind="optional",
                ),
            ),
            actions=("NoAction",),
            default_action="NoAction",
            default_action_args=(),
        )
        lines = []
        _emit_table(lines, tbl)
        joined = "\n".join(lines)
        self.assertIn(
            "headers.ipv4.isValid() || headers.ipv6.isValid(): optional;",
            joined,
        )


class TestTableKeyTypeWidened(absltest.TestCase):
    """Test that TableKey.field accepts Expression type."""

    def test_logical_op_key(self):
        key = nodes.TableKey(
            field=nodes.LogicalOp(
                op="||",
                left=nodes.IsValid(header_ref=nodes.FieldAccess(path=("hdr", "ipv4"))),
                right=nodes.IsValid(header_ref=nodes.FieldAccess(path=("hdr", "ipv6"))),
            ),
            match_kind="optional",
        )
        self.assertEqual(key.match_kind, "optional")
        self.assertIsInstance(key.field, nodes.LogicalOp)


if __name__ == "__main__":
    absltest.main()
