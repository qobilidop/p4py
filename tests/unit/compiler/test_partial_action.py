"""Tests for partial action application in table action lists."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch.v1model import V1Switch
from p4py.compiler import compile
from p4py.emitter.p4 import _emit_table


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


class TestPartialActionCompile(absltest.TestCase):
    def test_compile_partial_action_ref(self):
        """set_nexthop_id(local_metadata) in actions list."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def drop():
                pass

            @p4.action
            def set_nexthop_id(
                local_metadata: p4.inout(p4.bit(8)),
                nexthop_id: p4.bit(16),
            ):
                pass

            my_table = p4.table(
                key={hdr.ethernet.dstAddr: p4.exact},
                actions=[drop, set_nexthop_id(meta)],
                default_action=drop,
            )

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")

        table = ingress.tables[0]
        self.assertEqual(table.actions[0], "drop")
        self.assertEqual(table.actions[1], "set_nexthop_id(meta)")


class TestPartialActionEmit(absltest.TestCase):
    def test_emit_partial_action_in_table(self):
        table = nodes.TableDecl(
            name="my_table",
            keys=(
                nodes.TableKey(
                    field=nodes.FieldAccess(path=("hdr", "ethernet", "dstAddr")),
                    match_kind="exact",
                ),
            ),
            actions=("drop", "set_nexthop_id(local_metadata)"),
            default_action="drop",
            default_action_args=(),
        )
        lines = []
        _emit_table(lines, table)
        joined = "\n".join(lines)
        self.assertIn("set_nexthop_id(local_metadata);", joined)


if __name__ == "__main__":
    absltest.main()
