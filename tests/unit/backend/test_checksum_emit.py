"""Test that the emitter handles checksum controls."""

import p4py.lang as p4
from p4py.arch import v1model
from p4py.backend.p4 import emit
from p4py.compiler import compile


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


@p4.deparser
def TestDeparser(pkt, hdr):
    pkt.emit(hdr.ethernet)


class TestChecksumEmit:
    def test_checksum_controls_emitted(self):
        """Checksum controls emit verify/update_checksum calls."""
        main = v1model.V1Switch(
            parser=TestParser,
            verify_checksum=TestVerifyChecksum,
            ingress=TestIngress,
            compute_checksum=TestComputeChecksum,
            deparser=TestDeparser,
        )
        program = compile(main)
        p4_src = emit(program)
        assert "control TestVerifyChecksum(" in p4_src
        assert "verify_checksum(" in p4_src
        assert "hdr.ipv4.version" in p4_src
        assert "HashAlgorithm.csum16" in p4_src
        assert "control TestComputeChecksum(" in p4_src
        assert "update_checksum(" in p4_src
        # Main should use actual names
        assert "TestVerifyChecksum()" in p4_src
        assert "TestComputeChecksum()" in p4_src
        assert "MyVerifyChecksum()" not in p4_src
        assert "MyComputeChecksum()" not in p4_src

    def test_no_checksum_emits_empty_placeholder(self):
        """Pipeline without checksum emits empty stubs."""
        main = v1model.V1Switch(
            parser=TestParser,
            ingress=TestIngress,
            deparser=TestDeparser,
        )
        program = compile(main)
        p4_src = emit(program)
        assert "MyVerifyChecksum" in p4_src
        assert "MyComputeChecksum" in p4_src
