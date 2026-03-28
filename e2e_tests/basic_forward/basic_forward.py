"""Basic L2 forwarder in P4Py DSL.

Equivalent to basic_forward.p4: parses Ethernet, looks up dstAddr in an
exact-match table, and forwards to the specified port.
"""

import p4py.lang as p4
from p4py.arch import v1model


class ethernet_t(p4.header):
    dstAddr: p4.bit(48)
    srcAddr: p4.bit(48)
    etherType: p4.bit(16)


class headers_t(p4.struct):
    ethernet: ethernet_t


class metadata_t(p4.struct):
    pass


@p4.parser
def MyParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
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
        v1model.mark_to_drop(std_meta)

    mac_table = p4.table(
        key={hdr.ethernet.dstAddr: p4.exact},
        actions=[forward, drop],
        default_action=drop,
    )

    mac_table.apply()


@p4.deparser
def MyDeparser(pkt, hdr):
    pkt.emit(hdr.ethernet)


main = v1model.V1SwitchMini(
    parser=MyParser,
    ingress=MyIngress,
    deparser=MyDeparser,
)
