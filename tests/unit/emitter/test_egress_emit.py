"""Test that the emitter handles egress control blocks."""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch import v1model
from p4py.compiler import compile
from p4py.emitter.p4 import emit


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

    t = p4.table(
        key={hdr.ethernet.dstAddr: p4.exact},
        actions=[nop],
        default_action=nop,
    )

    t.apply()


@p4.control
def TestEgress(hdr, meta, std_meta):
    @p4.action
    def rewrite(src: p4.bit(48)):
        hdr.ethernet.srcAddr = src

    @p4.action
    def nop():
        pass

    mac_table = p4.table(
        key={hdr.ethernet.dstAddr: p4.exact},
        actions=[nop, rewrite],
        default_action=nop,
    )

    mac_table.apply()


@p4.deparser
def TestDeparser(pkt, hdr):
    pkt.emit(hdr.ethernet)


class TestEgressEmit(absltest.TestCase):
    def test_egress_emitted_with_tables(self):
        """Egress control emits actions, tables, and apply block."""
        main = v1model.V1Switch(
            parser=TestParser,
            ingress=TestIngress,
            egress=TestEgress,
            deparser=TestDeparser,
        )
        program = compile(main)
        p4_src = emit(program)
        # Egress block should contain the table and action
        self.assertIn("control TestEgress(", p4_src)
        self.assertIn("table mac_table {", p4_src)
        self.assertIn("action rewrite(bit<48> src)", p4_src)
        self.assertIn("mac_table.apply();", p4_src)
        # Main instantiation should use TestEgress, not MyEgress
        self.assertIn("TestEgress()", p4_src)
        self.assertNotIn("MyEgress()", p4_src)

    def test_no_egress_emits_empty_placeholder(self):
        """Pipeline without egress emits MyEgress with empty apply."""
        main = v1model.V1Switch(
            parser=TestParser,
            ingress=TestIngress,
            deparser=TestDeparser,
        )
        program = compile(main)
        p4_src = emit(program)
        self.assertIn("control MyEgress(", p4_src)
        self.assertIn("MyEgress()", p4_src)


if __name__ == "__main__":
    absltest.main()
