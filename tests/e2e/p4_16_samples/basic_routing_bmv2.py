"""Faithful basic_routing-bmv2 in P4Py DSL.

1:1 translation of p4lang/p4c testdata/p4_16_samples/basic_routing-bmv2.p4.
Remaining differences from upstream are tracked as TODOs.

See the original:
https://github.com/p4lang/p4c/blob/main/testdata/p4_16_samples/basic_routing-bmv2.p4
"""

import p4py.lang as p4
from p4py.arch import v1model


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


class ingress_metadata_t(p4.struct):
    vrf: p4.bit(12)
    bd: p4.bit(16)
    nexthop_index: p4.bit(16)


class metadata_t(p4.struct):
    ingress_metadata: ingress_metadata_t


@p4.parser
def ParserImpl(pkt, hdr: headers_t, meta: metadata_t, std_meta):
    def start():
        return parse_ethernet

    def parse_ethernet():
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
def egress(hdr, meta, std_meta):
    @p4.action
    def on_miss():
        pass

    @p4.action
    def rewrite_src_dst_mac(smac: p4.bit(48), dmac: p4.bit(48)):
        hdr.ethernet.srcAddr = smac
        hdr.ethernet.dstAddr = dmac

    rewrite_mac = p4.table(
        key={meta.ingress_metadata.nexthop_index: p4.exact},
        actions=[on_miss, rewrite_src_dst_mac],
        default_action=on_miss,
    )

    rewrite_mac.apply()


@p4.control
def ingress(hdr, meta, std_meta):
    @p4.action
    def on_miss():
        pass

    @p4.action
    def set_bd(bd: p4.bit(16)):
        meta.ingress_metadata.bd = bd

    @p4.action
    def set_vrf(vrf: p4.bit(12)):
        meta.ingress_metadata.vrf = vrf

    # TODO: Upstream has actions=[set_bd] only (no on_miss).
    port_mapping = p4.table(
        key={std_meta.ingress_port: p4.exact},
        actions=[on_miss, set_bd],
        default_action=on_miss,
    )

    # TODO: Upstream has actions=[set_vrf] only (no on_miss).
    bd = p4.table(
        key={meta.ingress_metadata.bd: p4.exact},
        actions=[on_miss, set_vrf],
        default_action=on_miss,
    )

    @p4.action
    def fib_hit_nexthop(nexthop_index: p4.bit(16)):
        meta.ingress_metadata.nexthop_index = nexthop_index
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1

    ipv4_fib = p4.table(
        key={
            meta.ingress_metadata.vrf: p4.exact,
            hdr.ipv4.dstAddr: p4.exact,
        },
        actions=[on_miss, fib_hit_nexthop],
        default_action=on_miss,
    )

    ipv4_fib_lpm = p4.table(
        key={
            meta.ingress_metadata.vrf: p4.exact,
            hdr.ipv4.dstAddr: p4.lpm,
        },
        actions=[on_miss, fib_hit_nexthop],
        default_action=on_miss,
    )

    @p4.action
    def set_egress_details(egress_spec: p4.bit(9)):
        std_meta.egress_spec = egress_spec

    nexthop = p4.table(
        key={meta.ingress_metadata.nexthop_index: p4.exact},
        actions=[on_miss, set_egress_details],
        default_action=on_miss,
    )

    if hdr.ipv4.isValid():
        port_mapping.apply()
        bd.apply()
        # Try exact FIB first; fall through to LPM on miss.
        match ipv4_fib.apply():
            case "on_miss":
                ipv4_fib_lpm.apply()
        nexthop.apply()


# TODO: Upstream uses condition=true, not hdr.ipv4.isValid().
@p4.control
def verifyChecksum(hdr, meta):
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
def computeChecksum(hdr, meta):
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
def DeparserImpl(pkt, hdr):
    pkt.emit(hdr.ethernet)
    pkt.emit(hdr.ipv4)


main = v1model.V1Switch(
    parser=ParserImpl,
    verify_checksum=verifyChecksum,
    ingress=ingress,
    egress=egress,
    compute_checksum=computeChecksum,
    deparser=DeparserImpl,
)
