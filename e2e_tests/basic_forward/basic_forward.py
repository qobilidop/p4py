"""Basic L2 forwarder in P4Py DSL.

Equivalent to basic_forward.p4: parses Ethernet, looks up dstAddr in an
exact-match table, and forwards to the specified port.
"""

import p4py.lang as p4
from p4py.arch.v1model import V1SwitchMini, mark_to_drop
from p4py.lang.bit import bit
from p4py.lang.header import header
from p4py.lang.struct import struct


class ethernet_t(header):
    dstAddr: bit(48)
    srcAddr: bit(48)
    etherType: bit(16)


class headers_t(struct):
    ethernet: ethernet_t


class metadata_t(struct):
    pass


@p4.parser
def MyParser(pkt, hdr, meta, std_meta):
    def start():
        pkt.extract(hdr.ethernet)
        return p4.ACCEPT


@p4.control
def MyIngress(hdr, meta, std_meta):
    @p4.action
    def forward(port: p4.bit(9)):
        std_meta.egress_spec = port

    @p4.action
    def drop():
        mark_to_drop(std_meta)

    mac_table = p4.table(
        key={hdr.ethernet.dstAddr: p4.exact},
        actions=[forward, drop],
        default_action=drop,
    )

    mac_table.apply()


@p4.deparser
def MyDeparser(pkt, hdr):
    pkt.emit(hdr.ethernet)


main = V1SwitchMini(
    headers=headers_t,
    metadata=metadata_t,
    parser=MyParser,
    ingress=MyIngress,
    deparser=MyDeparser,
)
