"""Test that checksum controls are compiled to IR."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
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
        """verify_checksum control produces FunctionCall IR node."""
        main = v1model.V1Switch(
            parser=TestParser,
            verify_checksum=TestVerifyChecksum,
            ingress=TestIngress,
            compute_checksum=TestComputeChecksum,
            deparser=TestDeparser,
        )
        package = compile(main)
        verify = _get_block(package, "verify_checksum")
        self.assertIsNotNone(verify)
        self.assertEqual(verify.name, "TestVerifyChecksum")
        self.assertLen(verify.apply_body, 1)
        stmt = verify.apply_body[0]
        self.assertIsInstance(stmt, nodes.FunctionCall)
        self.assertEqual(stmt.name, "verify_checksum")
        # 4 keyword args: condition, data, checksum, algo
        self.assertLen(stmt.args, 4)
        # condition is IsValid
        self.assertIsInstance(stmt.args[0], nodes.IsValid)
        # data is a ListExpression with 11 fields
        self.assertIsInstance(stmt.args[1], nodes.ListExpression)
        self.assertLen(stmt.args[1].elements, 11)
        self.assertEqual(
            stmt.args[1].elements[0],
            nodes.FieldAccess(path=("hdr", "ipv4", "version")),
        )
        # checksum is a FieldAccess
        self.assertEqual(
            stmt.args[2], nodes.FieldAccess(path=("hdr", "ipv4", "hdrChecksum"))
        )
        # algo is a FieldAccess (v1model.HashAlgorithm.csum16 → module stripped)
        self.assertIsInstance(stmt.args[3], nodes.FieldAccess)

    def test_compute_checksum_compiled(self):
        """update_checksum control produces FunctionCall IR node."""
        main = v1model.V1Switch(
            parser=TestParser,
            verify_checksum=TestVerifyChecksum,
            ingress=TestIngress,
            compute_checksum=TestComputeChecksum,
            deparser=TestDeparser,
        )
        package = compile(main)
        compute = _get_block(package, "compute_checksum")
        self.assertIsNotNone(compute)
        stmt = compute.apply_body[0]
        self.assertIsInstance(stmt, nodes.FunctionCall)
        self.assertEqual(stmt.name, "update_checksum")
        self.assertLen(stmt.args, 4)
        self.assertIsInstance(stmt.args[1], nodes.ListExpression)

    def test_no_checksum_produces_none(self):
        """Pipeline without checksum controls produces no checksum blocks."""
        main = v1model.V1Switch(
            parser=TestParser,
            ingress=TestIngress,
            deparser=TestDeparser,
        )
        package = compile(main)
        self.assertIsNone(_get_block(package, "verify_checksum"))
        self.assertIsNone(_get_block(package, "compute_checksum"))


if __name__ == "__main__":
    absltest.main()
