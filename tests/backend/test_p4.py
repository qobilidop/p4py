"""Tests for the P4-16 backend."""

import p4py.lang as p4
from p4py.arch.v1model import V1Switch, mark_to_drop
from p4py.backend.p4 import emit
from p4py.compiler import compile


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


class TestEmit:
    def test_ipv4_forwarder(self):
        @p4.parser
        def MyParser(pkt, hdr: headers_t, meta: metadata_t, std_meta):
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
        def MyIngress(hdr, meta, std_meta):
            @p4.action
            def forward(port: p4.bit(9)):
                std_meta.egress_spec = port
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1

            @p4.action
            def drop():
                mark_to_drop(std_meta)

            ipv4_table = p4.table(
                key={hdr.ipv4.dstAddr: p4.exact},
                actions=[forward, drop],
                default_action=drop,
            )

            if hdr.ipv4.isValid():
                ipv4_table.apply()
            else:
                drop()

        @p4.deparser
        def MyDeparser(pkt, hdr):
            pkt.emit(hdr.ethernet)
            pkt.emit(hdr.ipv4)

        pipeline = V1Switch(
            parser=MyParser,
            ingress=MyIngress,
            deparser=MyDeparser,
        )
        program = compile(pipeline)
        source = emit(program)

        # Verify key fragments are present in the emitted P4.
        assert "#include <core.p4>" in source
        assert "#include <v1model.p4>" in source

        assert "header ethernet_t {" in source
        assert "bit<48> dstAddr;" in source
        assert "header ipv4_t {" in source

        assert "struct headers_t {" in source
        assert "ethernet_t ethernet;" in source
        assert "struct metadata_t {" in source

        assert "parser MyParser(" in source
        assert "state start {" in source
        assert "pkt.extract(hdr.ethernet);" in source
        assert "transition select(hdr.ethernet.etherType)" in source
        assert "0x0800: parse_ipv4;" in source
        assert "default: accept;" in source
        assert "state parse_ipv4 {" in source

        assert "control MyIngress(" in source
        assert "action forward(bit<9> port)" in source
        assert "std_meta.egress_spec = port;" in source
        assert "hdr.ipv4.ttl = hdr.ipv4.ttl - 1;" in source
        assert "action drop()" in source
        assert "mark_to_drop(std_meta);" in source

        assert "table ipv4_table {" in source
        assert "hdr.ipv4.dstAddr: exact;" in source
        assert "actions = {" in source
        assert "default_action = drop();" in source

        assert "if (hdr.ipv4.isValid())" in source
        assert "ipv4_table.apply();" in source
        assert "} else {" in source

        assert "control MyDeparser(" in source
        assert "pkt.emit(hdr.ethernet);" in source
        assert "pkt.emit(hdr.ipv4);" in source

        # Boilerplate blocks
        assert "control MyVerifyChecksum(" in source
        assert "control MyEgress(" in source
        assert "control MyComputeChecksum(" in source
        assert "V1Switch(" in source
        assert ") main;" in source
