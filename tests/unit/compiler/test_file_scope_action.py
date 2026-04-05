"""Tests for file-scope (package-level) actions."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch.v1model import V1Switch
from p4py.compiler import compile
from p4py.emitter import p4 as emitter

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


class TestFileScopeActionCompile(absltest.TestCase):
    def test_compile_file_scope_action(self):
        @p4.action
        def set_nexthop_id(
            local_metadata: p4.inout(local_metadata_t),
            nexthop_id: nexthop_id_t,
        ):
            local_metadata.nexthop_id_valid = True
            local_metadata.nexthop_id_value = nexthop_id

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            pass

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
            file_scope_actions=(set_nexthop_id,),
        )
        package = compile(pipeline)

        self.assertLen(package.file_scope_actions, 1)
        action = package.file_scope_actions[0]
        self.assertEqual(action.name, "set_nexthop_id")
        self.assertLen(action.params, 2)
        self.assertEqual(action.params[0].direction, "inout")
        self.assertEqual(action.params[0].type_name, "local_metadata_t")
        self.assertEqual(action.params[1].type_name, "nexthop_id_t")
        self.assertLen(action.body, 2)


class TestFileScopeActionEmit(absltest.TestCase):
    def test_emit_file_scope_action(self):
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
            body=(
                nodes.Assignment(
                    target=nodes.FieldAccess(
                        path=("local_metadata", "nexthop_id_valid")
                    ),
                    value=nodes.BoolLiteral(value=True),
                ),
            ),
        )
        lines = []
        emitter._emit_file_scope_action(lines, action)
        joined = "\n".join(lines)
        self.assertIn("action set_nexthop_id(", joined)
        self.assertIn("inout local_metadata_t local_metadata", joined)
        self.assertIn("nexthop_id_t nexthop_id", joined)
        # File-scope actions have no indent on the action keyword
        self.assertTrue(lines[0].startswith("action "))


if __name__ == "__main__":
    absltest.main()
