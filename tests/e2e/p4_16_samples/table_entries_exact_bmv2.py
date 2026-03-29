"""Faithful table-entries-exact-bmv2 in P4Py DSL.

1:1 translation of p4lang/p4c testdata/p4_16_samples/table-entries-exact-bmv2.p4.

See the original:
https://github.com/p4lang/p4c/blob/main/testdata/p4_16_samples/table-entries-exact-bmv2.p4
"""

import p4py.lang as p4
from p4py.arch import v1model


class hdr(p4.header):
    e: p4.bit(8)
    t: p4.bit(16)
    l: p4.bit(8)
    r: p4.bit(8)
    v: p4.bit(8)


class Header_t(p4.struct):
    h: hdr


class Meta_t(p4.struct):
    pass


@p4.parser
def p_(pkt, hdr: Header_t, meta: Meta_t, std_meta):
    def start():
        pkt.extract(hdr.h)
        return p4.ACCEPT


@p4.control
def ingress(hdr, meta, std_meta):
    @p4.action
    def a():
        std_meta.egress_spec = p4.literal(0, width=9)

    @p4.action
    def a_with_control_params(x: p4.bit(9)):
        std_meta.egress_spec = x

    t_exact = p4.table(
        key={hdr.h.e: p4.exact},
        actions=[a, a_with_control_params],
        default_action=a,
        const_entries={
            p4.hex(0x01): a_with_control_params(1),
            p4.hex(0x02): a_with_control_params(2),
        },
    )

    t_exact.apply()


@p4.deparser
def deparser(pkt, hdr):
    pkt.emit(hdr.h)


main = v1model.V1Switch(
    parser=p_,
    ingress=ingress,
    deparser=deparser,
)
