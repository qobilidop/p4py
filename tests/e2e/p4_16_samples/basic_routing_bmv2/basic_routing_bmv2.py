"""Simplified basic_routing-bmv2 in P4Py DSL.

Adapted from p4lang/p4c testdata/p4_16_samples/basic_routing-bmv2.p4.
Implements IPv4 routing with LPM forwarding using the subset of P4
that P4Py currently supports.

See the original for the full program:
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


class metadata_t(p4.struct):
    nexthop_index: p4.bit(16)
    bd: p4.bit(16)
    vrf: p4.bit(12)


@p4.parser
def ParserImpl(pkt, hdr: headers_t, meta: metadata_t, std_meta):
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
def egress(hdr, meta, std_meta):
    @p4.action
    def on_miss():
        pass

    @p4.action
    def rewrite_mac(smac: p4.bit(48), dmac: p4.bit(48)):
        hdr.ethernet.srcAddr = smac
        hdr.ethernet.dstAddr = dmac

    rewrite_mac_table = p4.table(
        key={meta.nexthop_index: p4.exact},
        actions=[on_miss, rewrite_mac],
        default_action=on_miss,
    )

    rewrite_mac_table.apply()


@p4.control
def ingress(hdr, meta, std_meta):
    @p4.action
    def on_miss():
        pass

    @p4.action
    def set_bd(bd: p4.bit(16)):
        meta.bd = bd

    @p4.action
    def set_vrf(vrf: p4.bit(12)):
        meta.vrf = vrf

    port_mapping = p4.table(
        key={std_meta.ingress_port: p4.exact},
        actions=[on_miss, set_bd],
        default_action=on_miss,
    )

    bd_table = p4.table(
        key={meta.bd: p4.exact},
        actions=[on_miss, set_vrf],
        default_action=on_miss,
    )

    @p4.action
    def fib_hit_nexthop(nexthop_index: p4.bit(16)):
        meta.nexthop_index = nexthop_index
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1

    ipv4_fib = p4.table(
        key={hdr.ipv4.dstAddr: p4.exact},
        actions=[on_miss, fib_hit_nexthop],
        default_action=on_miss,
    )

    ipv4_fib_lpm = p4.table(
        key={hdr.ipv4.dstAddr: p4.lpm},
        actions=[on_miss, fib_hit_nexthop],
        default_action=on_miss,
    )

    @p4.action
    def set_egress_details(egress_spec: p4.bit(9)):
        std_meta.egress_spec = egress_spec

    nexthop = p4.table(
        key={meta.nexthop_index: p4.exact},
        actions=[on_miss, set_egress_details],
        default_action=on_miss,
    )

    port_mapping.apply()
    bd_table.apply()
    if hdr.ipv4.isValid():
        # Try exact FIB first; fall through to LPM on miss.
        match ipv4_fib.apply():
            case "on_miss":
                ipv4_fib_lpm.apply()
        nexthop.apply()


# TODO: Add verifyChecksum / computeChecksum controls.
# Requires: verify_checksum, update_checksum externs.


@p4.deparser
def DeparserImpl(pkt, hdr):
    pkt.emit(hdr.ethernet)
    pkt.emit(hdr.ipv4)


main = v1model.V1Switch(
    parser=ParserImpl,
    ingress=ingress,
    egress=egress,
    deparser=DeparserImpl,
)
