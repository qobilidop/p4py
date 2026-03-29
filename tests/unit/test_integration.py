"""End-to-end integration test: IPv4 forwarder in P4Py.

Writes the test program using the full DSL, compiles to IR, emits P4-16 source,
and simulates packet processing.
"""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch import v1model
from p4py.compiler import compile
from p4py.emitter.p4 import emit
from p4py.sim import simulate

# --- Type definitions ---


class ethernet_t(p4.header):
    dstAddr: p4.bit(48)
    srcAddr: p4.bit(48)
    etherType: p4.bit(16)


class ipv4_t(p4.header):
    version: p4.bit(4)
    ihl: p4.bit(4)
    diffserv: p4.bit(8)
    totalLen: p4.bit(16)
    identification: p4.bit(16)
    flags: p4.bit(3)
    fragOffset: p4.bit(13)
    ttl: p4.bit(8)
    protocol: p4.bit(8)
    hdrChecksum: p4.bit(16)
    srcAddr: p4.bit(32)
    dstAddr: p4.bit(32)


class headers_t(p4.struct):
    ethernet: ethernet_t
    ipv4: ipv4_t


class metadata_t(p4.struct):
    pass


# --- P4 program ---


@p4.parser
def MyParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
    def start():
        pkt.extract(hdr.ethernet)
        match hdr.ethernet.etherType:
            case 0x0800:
                return parse_ipv4
            case _:
                return p4.ACCEPT

    def parse_ipv4():
        pkt.extract(hdr.ipv4)
        return p4.ACCEPT


@p4.control
def MyIngress(hdr, meta, std_meta):
    @p4.action
    def forward(port: p4.bit(9)):
        std_meta.egress_spec = port
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1

    @p4.action
    def drop():
        v1model.mark_to_drop(std_meta)

    ipv4_table = p4.table(
        key={hdr.ipv4.dstAddr: p4.exact},
        actions=[forward, drop],
        default_action=drop,
    )

    if hdr.ipv4.isValid():
        ipv4_table.apply()
    else:
        drop()


@p4.deparser
def MyDeparser(pkt, hdr):
    pkt.emit(hdr.ethernet)
    pkt.emit(hdr.ipv4)


main = v1model.V1Switch(
    parser=MyParser,
    ingress=MyIngress,
    deparser=MyDeparser,
)

# --- Test packets ---

ETHERNET_HDR = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00"
IPV4_HDR = (
    b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
)
IPV4_PACKET = ETHERNET_HDR + IPV4_HDR
ARP_PACKET = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x06" + b"\x00" * 28

TABLE_ENTRIES = {
    "ipv4_table": [
        {
            "key": {"hdr.ipv4.dstAddr": 0x0A000002},
            "action": "forward",
            "args": {"port": 2},
        },
    ],
}


# --- Tests ---


class TestIntegration(absltest.TestCase):
    def test_compile_and_emit(self):
        """Compile to IR and emit valid P4-16 source."""
        program = compile(main)
        source = emit(program)

        # Should be parseable P4 — check key structure.
        self.assertIn("header ethernet_t {", source)
        self.assertIn("header ipv4_t {", source)
        self.assertIn("parser MyParser(", source)
        self.assertIn("control MyIngress(", source)
        self.assertIn("V1Switch(", source)
        self.assertIn(") main;", source)

    def test_simulate_forward(self):
        """IPv4 packet matching a table entry is forwarded."""
        program = compile(main)
        result = simulate(
            program,
            packet=IPV4_PACKET,
            ingress_port=1,
            table_entries=TABLE_ENTRIES,
        )
        self.assertFalse(result.dropped)
        self.assertEqual(result.egress_port, 2)
        # TTL decremented from 64 (0x40) to 63 (0x3f).
        self.assertEqual(result.packet[22], 63)

    def test_simulate_drop_no_entry(self):
        """IPv4 packet with no matching entry is dropped."""
        program = compile(main)
        result = simulate(
            program,
            packet=IPV4_PACKET,
            ingress_port=1,
            table_entries={},
        )
        self.assertTrue(result.dropped)

    def test_simulate_drop_non_ipv4(self):
        """Non-IPv4 packet is dropped (isValid check fails)."""
        program = compile(main)
        result = simulate(
            program,
            packet=ARP_PACKET,
            ingress_port=1,
            table_entries=TABLE_ENTRIES,
        )
        self.assertTrue(result.dropped)


if __name__ == "__main__":
    absltest.main()
