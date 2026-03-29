"""Test that checksum controls are compiled to IR."""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch import v1model
from p4py.compiler import compile
from p4py.ir import nodes


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


class TestChecksumCompile(absltest.TestCase):
    def test_verify_checksum_compiled(self):
        """verify_checksum control produces ChecksumVerify IR node."""
        main = v1model.V1Switch(
            parser=TestParser,
            verify_checksum=TestVerifyChecksum,
            ingress=TestIngress,
            compute_checksum=TestComputeChecksum,
            deparser=TestDeparser,
        )
        program = compile(main)
        self.assertIsNotNone(program.verify_checksum)
        self.assertEqual(program.verify_checksum.name, "TestVerifyChecksum")
        self.assertLen(program.verify_checksum.apply_body, 1)
        stmt = program.verify_checksum.apply_body[0]
        self.assertIsInstance(stmt, nodes.ChecksumVerify)
        self.assertIsInstance(stmt.condition, nodes.IsValid)
        self.assertLen(stmt.data, 11)
        self.assertEqual(
            stmt.data[0], nodes.FieldAccess(path=("hdr", "ipv4", "version"))
        )
        self.assertEqual(
            stmt.checksum, nodes.FieldAccess(path=("hdr", "ipv4", "hdrChecksum"))
        )
        self.assertEqual(stmt.algo, "csum16")

    def test_compute_checksum_compiled(self):
        """update_checksum control produces ChecksumUpdate IR node."""
        main = v1model.V1Switch(
            parser=TestParser,
            verify_checksum=TestVerifyChecksum,
            ingress=TestIngress,
            compute_checksum=TestComputeChecksum,
            deparser=TestDeparser,
        )
        program = compile(main)
        self.assertIsNotNone(program.compute_checksum)
        stmt = program.compute_checksum.apply_body[0]
        self.assertIsInstance(stmt, nodes.ChecksumUpdate)
        self.assertEqual(stmt.algo, "csum16")

    def test_no_checksum_produces_none(self):
        """Pipeline without checksum controls produces None."""
        main = v1model.V1Switch(
            parser=TestParser,
            ingress=TestIngress,
            deparser=TestDeparser,
        )
        program = compile(main)
        self.assertIsNone(program.verify_checksum)
        self.assertIsNone(program.compute_checksum)


if __name__ == "__main__":
    absltest.main()
