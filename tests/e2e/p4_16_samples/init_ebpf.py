"""Faithful init_ebpf in P4Py DSL.

1:1 translation of p4lang/p4c testdata/p4_16_samples/init_ebpf.p4.

See the original:
https://github.com/p4lang/p4c/blob/main/testdata/p4_16_samples/init_ebpf.p4
"""

import p4py.lang as p4
from p4py.arch import ebpf_model


class Ethernet(p4.header):
    destination: p4.bit(48)
    source: p4.bit(48)
    protocol: p4.bit(16)


class Headers_t(p4.struct):
    ethernet: Ethernet


@p4.parser
def prs(p, headers: Headers_t):
    def start():
        p.extract(headers.ethernet)
        return p4.ACCEPT


@p4.control
def pipe(headers: Headers_t, pass_):
    @p4.action
    def match(act: p4.bool):
        pass_ = act  # noqa: F841

    tbl = p4.table(
        key={headers.ethernet.protocol: p4.exact},
        actions=[match, p4.NoAction],
        const_entries={
            p4.hex(0x0800): match(True),
            p4.hex(0xD000): match(False),
        },
        implementation=ebpf_model.hash_table(64),
    )

    pass_ = True  # noqa: F841
    tbl.apply()


main = ebpf_model.ebpfFilter(parser=prs, filter=pipe)
