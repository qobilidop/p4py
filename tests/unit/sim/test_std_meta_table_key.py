"""Test that std_meta fields can be used as table keys."""

import p4py.lang as p4
from p4py.arch import v1model
from p4py.compiler import compile
from p4py.sim import simulate


class ethernet_t(p4.header):
    dstAddr: p4.bit(48)
    srcAddr: p4.bit(48)
    etherType: p4.bit(16)


class headers_t(p4.struct):
    ethernet: ethernet_t


class metadata_t(p4.struct):
    pass


@p4.parser
def TestParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
    def start():
        pkt.extract(hdr.ethernet)
        return p4.ACCEPT


@p4.control
def TestIngress(hdr, meta, std_meta):
    @p4.action
    def set_egress(port: p4.bit(9)):
        std_meta.egress_spec = port

    @p4.action
    def nop():
        pass

    port_table = p4.table(
        key={std_meta.ingress_port: p4.exact},
        actions=[nop, set_egress],
        default_action=nop,
    )

    port_table.apply()


@p4.deparser
def TestDeparser(pkt, hdr):
    pkt.emit(hdr.ethernet)


main = v1model.V1Switch(
    parser=TestParser,
    ingress=TestIngress,
    deparser=TestDeparser,
)


class TestStdMetaTableKey:
    def test_exact_match_on_ingress_port(self):
        """Table with std_meta.ingress_port as exact key routes correctly."""
        program = compile(main)
        packet = b"\x00" * 14  # minimal ethernet
        entries = {
            "port_table": [
                {
                    "key": {"std_meta.ingress_port": 3},
                    "action": "set_egress",
                    "args": {"port": 7},
                },
            ],
        }
        result = simulate(program, packet=packet, ingress_port=3, table_entries=entries)
        assert result.egress_port == 7

    def test_no_match_uses_default(self):
        """When ingress_port doesn't match any entry, default action runs."""
        program = compile(main)
        packet = b"\x00" * 14
        entries = {
            "port_table": [
                {
                    "key": {"std_meta.ingress_port": 3},
                    "action": "set_egress",
                    "args": {"port": 7},
                },
            ],
        }
        result = simulate(program, packet=packet, ingress_port=5, table_entries=entries)
        assert result.egress_port == 0  # default nop, egress_spec stays 0
