"""Simplified basic_routing-bmv2 in P4Py DSL.

Adapted from p4lang/p4c testdata/p4_16_samples/basic_routing-bmv2.p4.
Implements IPv4 routing with LPM forwarding using the subset of P4
that P4Py currently supports.

See the original for the full program:
https://github.com/p4lang/p4c/blob/main/testdata/p4_16_samples/basic_routing-bmv2.p4
"""

import p4py.lang as p4
from p4py.arch import v1model

# TODO: Add ingress_metadata_t struct with bit<> fields:
#   vrf: bit<12>, bd: bit<16>, nexthop_index: bit<16>
# Requires: metadata struct with non-header fields.


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


# TODO: Add egress control with rewrite_mac table.
# Requires: egress pipeline support in V1Switch.


@p4.control
def ingress(hdr, meta, std_meta):
    # TODO: Add port_mapping table (exact on ingress_port → set_bd).
    # TODO: Add bd table (exact on bd → set_vrf).
    # Requires: metadata struct with non-header fields.

    @p4.action
    def forward(port: p4.bit(9)):
        std_meta.egress_spec = port
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1

    @p4.action
    def drop():
        v1model.mark_to_drop(std_meta)

    # The original uses both an exact-match ipv4_fib and an lpm ipv4_fib_lpm
    # with a switch on action_run to fall through. We simplify to a single
    # LPM table.
    # TODO: Add ipv4_fib exact table + switch on action_run fallthrough.
    # Requires: switch statement, action_run.
    ipv4_lpm = p4.table(
        key={hdr.ipv4.dstAddr: p4.lpm},
        actions=[forward, drop],
        default_action=drop,
    )

    # TODO: Add nexthop table (exact on nexthop_index → set_egress_details).
    # Requires: metadata struct with non-header fields.

    if hdr.ipv4.isValid():
        ipv4_lpm.apply()
    else:
        drop()


# TODO: Add verifyChecksum / computeChecksum controls.
# Requires: verify_checksum, update_checksum externs.


@p4.deparser
def DeparserImpl(pkt, hdr):
    pkt.emit(hdr.ethernet)
    pkt.emit(hdr.ipv4)


main = v1model.V1Switch(
    parser=ParserImpl,
    ingress=ingress,
    deparser=DeparserImpl,
)
