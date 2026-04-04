"""Tests for table.apply().hit expression."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch.v1model import V1Switch
from p4py.compiler import compile
from p4py.emitter.p4 import _emit_statement


class ethernet_t(p4.header):
    dstAddr: p4.bit(48)
    srcAddr: p4.bit(48)
    etherType: p4.bit(16)


class headers_t(p4.struct):
    ethernet: ethernet_t


class metadata_t(p4.struct):
    route_hit: p4.bool_


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


class TestTableApplyHitIR(absltest.TestCase):
    def test_table_apply_hit_node(self):
        node = nodes.TableApplyHit(table_name="my_table")
        self.assertEqual(node.table_name, "my_table")


class TestTableApplyHitCompile(absltest.TestCase):
    def test_compile_apply_hit_assignment(self):
        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def noop():
                pass

            my_table = p4.table(
                key={hdr.ethernet.dstAddr: p4.exact},
                actions=[noop],
                default_action=noop,
            )

            meta.route_hit = my_table.apply().hit

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")

        self.assertLen(ingress.apply_body, 1)
        stmt = ingress.apply_body[0]
        self.assertIsInstance(stmt, nodes.Assignment)
        self.assertIsInstance(stmt.value, nodes.TableApplyHit)
        self.assertEqual(stmt.value.table_name, "my_table")


class TestTableApplyHitEmit(absltest.TestCase):
    def test_emit_apply_hit_assignment(self):
        stmt = nodes.Assignment(
            target=nodes.FieldAccess(path=("meta", "route_hit")),
            value=nodes.TableApplyHit(table_name="my_table"),
        )
        result = _emit_statement(stmt)
        self.assertEqual(result, "meta.route_hit = my_table.apply().hit;")


if __name__ == "__main__":
    absltest.main()
