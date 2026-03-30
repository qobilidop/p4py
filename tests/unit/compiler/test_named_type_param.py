"""Tests for named type action parameters."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch.v1model import V1Switch
from p4py.compiler import compile
from p4py.emitter.p4 import _emit_action


# --- Type fixtures ---

vrf_id_t = p4.typedef(p4.bit(10), "vrf_id_t")


class ethernet_t(p4.header):
    dstAddr: p4.bit(48)
    srcAddr: p4.bit(48)
    etherType: p4.bit(16)


class headers_t(p4.struct):
    ethernet: ethernet_t


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


class TestNamedTypeActionParam(absltest.TestCase):
    """Test that action params with named types compile and emit correctly."""

    def test_compile_named_type_param(self):
        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def set_vrf(vrf_id: vrf_id_t):
                pass

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)

        ingress = _get_block(package, "ingress")
        self.assertLen(ingress.actions, 1)
        action = ingress.actions[0]
        self.assertEqual(action.name, "set_vrf")
        self.assertLen(action.params, 1)

        param = action.params[0]
        self.assertEqual(param.name, "vrf_id")
        self.assertEqual(param.type_name, "vrf_id_t")
        self.assertIsNone(param.type)

    def test_emit_named_type_param(self):
        action = nodes.ActionDecl(
            name="set_vrf",
            params=(nodes.ActionParam(name="vrf_id", type_name="vrf_id_t"),),
            body=(),
        )
        lines = []
        _emit_action(lines, action)
        self.assertIn("    action set_vrf(vrf_id_t vrf_id) {", lines)

    def test_emit_mixed_params(self):
        action = nodes.ActionDecl(
            name="set_stuff",
            params=(
                nodes.ActionParam(name="vrf_id", type_name="vrf_id_t"),
                nodes.ActionParam(name="port", type=nodes.BitType(9)),
                nodes.ActionParam(name="flag", type=nodes.BoolType()),
            ),
            body=(),
        )
        lines = []
        _emit_action(lines, action)
        self.assertIn(
            "    action set_stuff(vrf_id_t vrf_id, bit<9> port, bool flag) {",
            lines,
        )


class TestNamedTypeIRNode(absltest.TestCase):
    def test_action_param_with_type_name(self):
        p = nodes.ActionParam(name="vrf_id", type_name="vrf_id_t")
        self.assertEqual(p.name, "vrf_id")
        self.assertEqual(p.type_name, "vrf_id_t")
        self.assertIsNone(p.type)

    def test_action_param_backward_compatible(self):
        p = nodes.ActionParam(name="port", type=nodes.BitType(9))
        self.assertEqual(p.name, "port")
        self.assertIsNone(p.type_name)


if __name__ == "__main__":
    absltest.main()
