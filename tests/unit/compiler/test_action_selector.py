"""Tests for action_selector declaration and selector match kind."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch import v1model
from p4py.arch.v1model import V1Switch
from p4py.compiler import compile
from p4py.emitter.p4 import _emit_action_selector, _emit_table


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


class TestActionSelectorIR(absltest.TestCase):
    def test_action_selector_node(self):
        node = nodes.ActionSelector(
            name="wcmp_group_selector",
            algorithm="HashAlgorithm.identity",
            size=31296,
            width=16,
        )
        self.assertEqual(node.name, "wcmp_group_selector")
        self.assertEqual(node.algorithm, "HashAlgorithm.identity")
        self.assertEqual(node.size, 31296)
        self.assertEqual(node.width, 16)


class TestActionSelectorEmit(absltest.TestCase):
    def test_emit_action_selector(self):
        node = nodes.ActionSelector(
            name="wcmp_group_selector",
            algorithm="HashAlgorithm.identity",
            size=31296,
            width=16,
        )
        lines = []
        _emit_action_selector(lines, node)
        joined = "\n".join(lines)
        self.assertIn("action_selector(HashAlgorithm.identity,", joined)
        self.assertIn("31296,", joined)
        self.assertIn("16) wcmp_group_selector;", joined)


class TestSelectorMatchKindEmit(absltest.TestCase):
    def test_emit_selector_key(self):
        table = nodes.TableDecl(
            name="wcmp_group_table",
            keys=(
                nodes.TableKey(
                    field=nodes.FieldAccess(
                        path=("local_metadata", "wcmp_group_id_value")
                    ),
                    match_kind="exact",
                ),
                nodes.TableKey(
                    field=nodes.FieldAccess(
                        path=("local_metadata", "wcmp_selector_input")
                    ),
                    match_kind="selector",
                ),
            ),
            actions=("set_nexthop_id(local_metadata)",),
            default_action="NoAction",
            default_action_args=(),
            implementation="wcmp_group_selector",
        )
        lines = []
        _emit_table(lines, table)
        joined = "\n".join(lines)
        self.assertIn("selector;", joined)
        self.assertIn("implementation = wcmp_group_selector;", joined)


class TestActionSelectorCompile(absltest.TestCase):
    def test_compile_action_selector(self):
        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def noop():
                pass

            my_selector = p4.action_selector(
                v1model.HashAlgorithm.identity, 31296, 16
            )

            my_table = p4.table(
                key={
                    hdr.ethernet.dstAddr: p4.exact,
                    hdr.ethernet.srcAddr: p4.selector,
                },
                actions=[noop],
                default_action=noop,
                implementation=my_selector,
            )

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")

        self.assertLen(ingress.action_selectors, 1)
        sel = ingress.action_selectors[0]
        self.assertEqual(sel.name, "my_selector")
        self.assertEqual(sel.algorithm, "HashAlgorithm.identity")
        self.assertEqual(sel.size, 31296)
        self.assertEqual(sel.width, 16)

        table = ingress.tables[0]
        self.assertEqual(table.keys[1].match_kind, "selector")
        self.assertEqual(table.implementation, "my_selector")


if __name__ == "__main__":
    absltest.main()
