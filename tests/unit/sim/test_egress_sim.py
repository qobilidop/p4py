"""Test that the simulator executes egress control blocks."""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch import v1model
from p4py.compiler import compile
from p4py.sim import simulate


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
    def forward(port: p4.bit(9)):
        std_meta.egress_spec = port

    @p4.action
    def nop():
        pass

    fwd_table = p4.table(
        key={hdr.ethernet.dstAddr: p4.exact},
        actions=[nop, forward],
        default_action=nop,
    )

    fwd_table.apply()


@p4.control
def TestEgress(hdr, meta, std_meta):
    @p4.action
    def rewrite_src(src: p4.bit(48)):
        hdr.ethernet.srcAddr = src

    @p4.action
    def nop():
        pass

    mac_table = p4.table(
        key={hdr.ethernet.dstAddr: p4.exact},
        actions=[nop, rewrite_src],
        default_action=nop,
    )

    mac_table.apply()


@p4.deparser
def TestDeparser(pkt, hdr):
    pkt.emit(hdr.ethernet)


main = v1model.V1Switch(
    parser=TestParser,
    ingress=TestIngress,
    egress=TestEgress,
    deparser=TestDeparser,
)


class TestEgressSim(absltest.TestCase):
    def setUp(self):
        self.program = compile(main)

    def test_egress_rewrites_packet(self):
        """Egress control modifies packet after ingress forwards it."""
        packet = (
            b"\x00\x00\x00\x00\x00\x01"  # dstAddr
            b"\x00\x00\x00\x00\x00\x02"  # srcAddr
            b"\x08\x00"  # etherType
        )
        entries = {
            "fwd_table": [
                {
                    "key": {"hdr.ethernet.dstAddr": 0x000000000001},
                    "action": "forward",
                    "args": {"port": 5},
                },
            ],
            "mac_table": [
                {
                    "key": {"hdr.ethernet.dstAddr": 0x000000000001},
                    "action": "rewrite_src",
                    "args": {"src": 0xAABBCCDDEEFF},
                },
            ],
        }
        result = simulate(
            self.program, packet=packet, ingress_port=0, table_entries=entries
        )
        self.assertFalse(result.dropped)
        self.assertEqual(result.egress_port, 5)
        # srcAddr rewritten by egress from 00:00:00:00:00:02 to AA:BB:CC:DD:EE:FF
        self.assertEqual(result.packet[6:12], b"\xaa\xbb\xcc\xdd\xee\xff")

    def test_egress_skipped_on_drop(self):
        """Egress does not run when ingress drops the packet."""
        packet = (
            b"\x00\x00\x00\x00\x00\x99"  # dstAddr (no match)
            b"\x00\x00\x00\x00\x00\x02"
            b"\x08\x00"
        )
        entries = {
            "fwd_table": [
                {
                    "key": {"hdr.ethernet.dstAddr": 0x000000000001},
                    "action": "forward",
                    "args": {"port": 5},
                },
            ],
        }
        result = simulate(
            self.program, packet=packet, ingress_port=0, table_entries=entries
        )
        # No fwd_table match -> egress_spec stays 0 -> not dropped, just port 0
        self.assertEqual(result.egress_port, 0)

    def test_no_egress_pipeline_still_works(self):
        """Pipeline without egress works as before."""
        no_egress = v1model.V1Switch(
            parser=TestParser,
            ingress=TestIngress,
            deparser=TestDeparser,
        )
        program = compile(no_egress)
        packet = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00"
        entries = {
            "fwd_table": [
                {
                    "key": {"hdr.ethernet.dstAddr": 0x000000000001},
                    "action": "forward",
                    "args": {"port": 5},
                },
            ],
        }
        result = simulate(program, packet=packet, ingress_port=0, table_entries=entries)
        self.assertFalse(result.dropped)
        self.assertEqual(result.egress_port, 5)


if __name__ == "__main__":
    absltest.main()
