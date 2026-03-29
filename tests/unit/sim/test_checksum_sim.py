"""Test that the simulator executes checksum verify and update."""

import p4py.lang as p4
from p4py.arch import v1model
from p4py.compiler import compile
from p4py.sim import simulate


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


@p4.parser
def TestParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
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
def TestVerifyChecksum(hdr, meta):
    v1model.verify_checksum(
        condition=hdr.ipv4.isValid(),
        data=[
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
        ],
        checksum=hdr.ipv4.hdrChecksum,
        algo=v1model.HashAlgorithm.csum16,
    )


@p4.control
def TestIngress(hdr, meta, std_meta):
    @p4.action
    def forward(port: p4.bit(9)):
        std_meta.egress_spec = port
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1

    @p4.action
    def nop():
        pass

    t = p4.table(
        key={hdr.ipv4.dstAddr: p4.exact},
        actions=[nop, forward],
        default_action=nop,
    )

    if hdr.ipv4.isValid():
        t.apply()


@p4.control
def TestComputeChecksum(hdr, meta):
    v1model.update_checksum(
        condition=hdr.ipv4.isValid(),
        data=[
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
        ],
        checksum=hdr.ipv4.hdrChecksum,
        algo=v1model.HashAlgorithm.csum16,
    )


@p4.deparser
def TestDeparser(pkt, hdr):
    pkt.emit(hdr.ethernet)
    pkt.emit(hdr.ipv4)


main = v1model.V1Switch(
    parser=TestParser,
    verify_checksum=TestVerifyChecksum,
    ingress=TestIngress,
    compute_checksum=TestComputeChecksum,
    deparser=TestDeparser,
)


def _compute_ipv4_checksum(ipv4_bytes: bytes) -> int:
    """Compute the IPv4 header checksum (RFC 1071)."""
    data = bytearray(ipv4_bytes)
    data[10] = 0
    data[11] = 0
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class TestChecksumSim:
    def setup_method(self):
        self.program = compile(main)

    def test_update_checksum_recomputes_after_ttl_change(self):
        """update_checksum recalculates checksum after TTL decrement."""
        # Build IPv4 header with valid checksum.
        ipv4_no_csum = (
            b"\x45\x00\x00\x14"  # ver=4, ihl=5, totalLen=20
            b"\x00\x00\x00\x00"  # id, flags, fragOffset
            b"\x40\x06"  # ttl=64, protocol=6
            b"\x00\x00"  # checksum placeholder
            b"\x0a\x00\x00\x01"  # src=10.0.0.1
            b"\x0a\x00\x00\x02"  # dst=10.0.0.2
        )
        original_csum = _compute_ipv4_checksum(ipv4_no_csum)
        ipv4_hdr = bytearray(ipv4_no_csum)
        ipv4_hdr[10] = (original_csum >> 8) & 0xFF
        ipv4_hdr[11] = original_csum & 0xFF

        ethernet_hdr = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00"
        packet = ethernet_hdr + bytes(ipv4_hdr)

        entries = {
            "t": [
                {
                    "key": {"hdr.ipv4.dstAddr": 0x0A000002},
                    "action": "forward",
                    "args": {"port": 5},
                },
            ],
        }
        result = simulate(
            self.program,
            packet=packet,
            ingress_port=0,
            table_entries=entries,
        )
        assert not result.dropped
        assert result.egress_port == 5
        # TTL decremented: 64 -> 63
        assert result.packet[22] == 63
        # Checksum should be recomputed for the new TTL.
        output_ipv4 = result.packet[14:34]
        expected_csum = _compute_ipv4_checksum(output_ipv4)
        actual_csum = (output_ipv4[10] << 8) | output_ipv4[11]
        assert actual_csum == expected_csum

    def test_checksum_not_updated_when_condition_false(self):
        """update_checksum skips when condition is false (invalid header)."""
        arp_packet = (
            b"\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x02"
            b"\x08\x06"  # ARP
            b"\x00" * 6
        )
        result = simulate(
            self.program,
            packet=arp_packet,
            ingress_port=0,
            table_entries={},
        )
        # Packet passes through unchanged.
        assert not result.dropped
        assert result.packet == arp_packet
