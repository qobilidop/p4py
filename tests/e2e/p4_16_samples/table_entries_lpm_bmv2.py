"""Faithful table-entries-lpm-bmv2 in P4Py DSL.

1:1 translation of p4lang/p4c testdata/p4_16_samples/table-entries-lpm-bmv2.p4.

See the original:
https://github.com/p4lang/p4c/blob/main/testdata/p4_16_samples/table-entries-lpm-bmv2.p4
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
def p(b, h: Header_t, m: Meta_t, sm):
    def start():
        b.extract(h.h)
        return p4.ACCEPT


@p4.control
def ingress(h, m, standard_meta):
    @p4.action
    def a():
        standard_meta.egress_spec = 0

    @p4.action
    def a_with_control_params(x: p4.bit(9)):
        standard_meta.egress_spec = x

    t_lpm = p4.table(
        key={h.h.l: p4.lpm},
        actions=[a, a_with_control_params],
        default_action=a,
        const_entries={
            p4.mask(p4.hex(0x11), p4.hex(0xF0)): a_with_control_params(11),
            p4.hex(0x12): a_with_control_params(12),
            None: a_with_control_params(13),
        },
    )

    t_lpm.apply()


@p4.deparser
def deparser(b, h):
    b.emit(h.h)


main = v1model.V1Switch(
    parser=p,
    ingress=ingress,
    deparser=deparser,
)
