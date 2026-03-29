"""Test that egress control blocks are compiled to IR."""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch import v1model
from p4py.compiler import compile


def _get_block(package, name):
    """Get a block declaration from a Package by name."""
    for entry in package.blocks:
        if entry.name == name:
            return entry.decl
    return None


class ethernet_t(p4.header):
    dstAddr: p4.bit(48)
    srcAddr: p4.bit(48)
    etherType: p4.bit(16)


class headers_t(p4.struct):
    ethernet: ethernet_t


class metadata_t(p4.struct):
    pass


@p4.parser
def TestParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
    def start():
        pkt.extract(hdr.ethernet)
        return p4.ACCEPT


@p4.control
def TestIngress(hdr, meta, std_meta):
    @p4.action
    def nop():
        pass

    pass_table = p4.table(
        key={hdr.ethernet.dstAddr: p4.exact},
        actions=[nop],
        default_action=nop,
    )

    pass_table.apply()


@p4.control
def TestEgress(hdr, meta, std_meta):
    @p4.action
    def rewrite(src: p4.bit(48)):
        hdr.ethernet.srcAddr = src

    @p4.action
    def nop():
        pass

    rewrite_table = p4.table(
        key={hdr.ethernet.dstAddr: p4.exact},
        actions=[nop, rewrite],
        default_action=nop,
    )

    rewrite_table.apply()


@p4.deparser
def TestDeparser(pkt, hdr):
    pkt.emit(hdr.ethernet)


class TestEgressCompile(absltest.TestCase):
    def test_egress_compiled_to_ir(self):
        """Pipeline with egress produces IR with egress ControlDecl."""
        main = v1model.V1Switch(
            parser=TestParser,
            ingress=TestIngress,
            egress=TestEgress,
            deparser=TestDeparser,
        )
        package = compile(main)
        egress = _get_block(package, "egress")
        self.assertIsNotNone(egress)
        self.assertEqual(egress.name, "TestEgress")
        self.assertLen(egress.actions, 2)
        self.assertLen(egress.tables, 1)
        self.assertEqual(egress.tables[0].name, "rewrite_table")

    def test_no_egress_produces_none(self):
        """Pipeline without egress produces no egress block."""
        main = v1model.V1Switch(
            parser=TestParser,
            ingress=TestIngress,
            deparser=TestDeparser,
        )
        package = compile(main)
        self.assertIsNone(_get_block(package, "egress"))


if __name__ == "__main__":
    absltest.main()
