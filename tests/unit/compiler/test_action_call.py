"""Tests for action calling another action."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch.v1model import V1Switch
from p4py.compiler import compile
from p4py.emitter.p4 import _emit_action


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


class TestActionCallCompile(absltest.TestCase):
    def test_action_calls_another_action(self):
        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def inner_action(port: p4.bit(9)):
                std_meta.egress_spec = port

            @p4.action
            def outer_action(port: p4.bit(9)):
                inner_action(port)

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")

        outer = next(a for a in ingress.actions if a.name == "outer_action")
        self.assertLen(outer.body, 1)
        call = outer.body[0]
        self.assertIsInstance(call, nodes.FunctionCall)
        self.assertEqual(call.name, "inner_action")


class TestActionCallEmit(absltest.TestCase):
    def test_emit_action_calling_action(self):
        action = nodes.ActionDecl(
            name="outer",
            params=(nodes.ActionParam(name="port", type=nodes.BitType(9)),),
            body=(
                nodes.FunctionCall(
                    name="inner",
                    args=(nodes.FieldAccess(path=("port",)),),
                ),
            ),
        )
        lines = []
        _emit_action(lines, action)
        self.assertIn("        inner(port);", lines)


if __name__ == "__main__":
    absltest.main()
