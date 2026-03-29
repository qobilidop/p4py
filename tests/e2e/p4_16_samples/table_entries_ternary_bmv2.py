"""Faithful table-entries-ternary-bmv2 in P4Py DSL.

1:1 translation of p4lang/p4c testdata/p4_16_samples/table-entries-ternary-bmv2.p4.

See the original:
https://github.com/p4lang/p4c/blob/main/testdata/p4_16_samples/table-entries-ternary-bmv2.p4
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

    t_ternary = p4.table(
        key={h.h.t: p4.ternary},
        actions=[a, a_with_control_params],
        default_action=a,
        const_entries={
            p4.mask(p4.hex(0x1111), p4.hex(0xF)): a_with_control_params(1),
            p4.hex(0x1187): a_with_control_params(2),
            p4.mask(p4.hex(0x1111), p4.hex(0xF000)): a_with_control_params(3),
            None: a_with_control_params(4),
        },
    )

    t_ternary.apply()


@p4.deparser
def deparser(b, h):
    b.emit(h.h)


main = v1model.V1Switch(
    parser=p,
    ingress=ingress,
    deparser=deparser,
)
