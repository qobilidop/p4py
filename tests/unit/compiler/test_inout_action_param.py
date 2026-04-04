"""Tests for inout direction on action parameters."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch.v1model import V1Switch
from p4py.compiler import compile
from p4py.emitter.p4 import _emit_action


local_metadata_t = p4.newtype(p4.bit(8), "local_metadata_t")
nexthop_id_t = p4.newtype(p4.bit(16), "nexthop_id_t")


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


class TestInoutActionParamIR(absltest.TestCase):
    def test_action_param_with_direction(self):
        p = nodes.ActionParam(
            name="local_metadata", type_name="local_metadata_t", direction="inout"
        )
        self.assertEqual(p.direction, "inout")
        self.assertEqual(p.type_name, "local_metadata_t")

    def test_action_param_no_direction(self):
        p = nodes.ActionParam(name="port", type=nodes.BitType(9))
        self.assertIsNone(p.direction)


class TestInoutActionParamCompile(absltest.TestCase):
    def test_compile_inout_param(self):
        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def set_nexthop(
                local_metadata: p4.inout(local_metadata_t),
                nexthop_id: nexthop_id_t,
            ):
                pass

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")

        action = ingress.actions[0]
        self.assertEqual(action.name, "set_nexthop")
        self.assertLen(action.params, 2)

        param0 = action.params[0]
        self.assertEqual(param0.name, "local_metadata")
        self.assertEqual(param0.type_name, "local_metadata_t")
        self.assertEqual(param0.direction, "inout")

        param1 = action.params[1]
        self.assertEqual(param1.name, "nexthop_id")
        self.assertEqual(param1.type_name, "nexthop_id_t")
        self.assertIsNone(param1.direction)


class TestInoutActionParamEmit(absltest.TestCase):
    def test_emit_inout_param(self):
        action = nodes.ActionDecl(
            name="set_nexthop_id",
            params=(
                nodes.ActionParam(
                    name="local_metadata",
                    type_name="local_metadata_t",
                    direction="inout",
                ),
                nodes.ActionParam(name="nexthop_id", type_name="nexthop_id_t"),
            ),
            body=(),
        )
        lines = []
        _emit_action(lines, action)
        self.assertIn(
            "    action set_nexthop_id("
            "inout local_metadata_t local_metadata, "
            "nexthop_id_t nexthop_id) {",
            lines,
        )


if __name__ == "__main__":
    absltest.main()
