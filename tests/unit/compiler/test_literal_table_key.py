"""Tests for literal values as table keys."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch.v1model import V1Switch
from p4py.compiler import compile


class ethernet_t(p4.header):
    dstAddr: p4.bit(48)
    srcAddr: p4.bit(48)
    etherType: p4.bit(16)


class headers_t(p4.struct):
    ethernet: ethernet_t


class metadata_t(p4.struct):
    pass


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


def _get_block(package, name):
    for entry in package.blocks:
        if entry.name == name:
            return entry.decl
    return None


class TestLiteralTableKey(absltest.TestCase):
    def test_compile_literal_key(self):
        """p4.literal(1, width=1) as table key compiles to IntLiteral."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def nop():
                pass

            my_table = p4.table(  # noqa: F841
                key={
                    p4.literal(1, width=1): p4.ternary,
                    hdr.ethernet.dstAddr: p4.exact,
                },
                actions=[nop],
                default_action=nop,
            )

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

        # First key: literal
        self.assertIsInstance(tbl.keys[0].field, nodes.IntLiteral)
        self.assertEqual(tbl.keys[0].field.value, 1)
        self.assertEqual(tbl.keys[0].field.width, 1)
        self.assertEqual(tbl.keys[0].match_kind, "ternary")

        # Second key: field access (still works)
        self.assertIsInstance(tbl.keys[1].field, nodes.FieldAccess)
        self.assertEqual(tbl.keys[1].match_kind, "exact")

    def test_emit_literal_key(self):
        """Literal table key emits as '1w1 : ternary;'."""
        from p4py.emitter.p4 import emit

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def nop():
                pass

            my_table = p4.table(  # noqa: F841
                key={
                    p4.literal(1, width=1): p4.ternary,
                },
                actions=[nop],
                default_action=nop,
            )

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        output = emit(package)

        self.assertIn("1w1: ternary;", output)


if __name__ == "__main__":
    absltest.main()
