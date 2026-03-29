"""Tests for the P4-16 backend."""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch import ebpf_model
from p4py.arch.ebpf_model import ebpfFilter, hash_table
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


class TestEmit(absltest.TestCase):
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
        self.assertIn("#include <core.p4>", source)
        self.assertIn("#include <v1model.p4>", source)

        self.assertIn("header ethernet_t {", source)
        self.assertIn("bit<48> dstAddr;", source)
        self.assertIn("header ipv4_t {", source)

        self.assertIn("struct headers_t {", source)
        self.assertIn("ethernet_t ethernet;", source)
        self.assertIn("struct metadata_t {", source)

        self.assertIn("parser MyParser(", source)
        self.assertIn("state start {", source)
        self.assertIn("pkt.extract(hdr.ethernet);", source)
        self.assertIn("transition select(hdr.ethernet.etherType)", source)
        self.assertIn("0x0800: parse_ipv4;", source)
        self.assertIn("default: accept;", source)
        self.assertIn("state parse_ipv4 {", source)

        self.assertIn("control MyIngress(", source)
        self.assertIn("action forward(bit<9> port)", source)
        self.assertIn("std_meta.egress_spec = port;", source)
        self.assertIn("hdr.ipv4.ttl = hdr.ipv4.ttl - 1;", source)
        self.assertIn("action drop()", source)
        self.assertIn("mark_to_drop(std_meta);", source)

        self.assertIn("table ipv4_table {", source)
        self.assertIn("hdr.ipv4.dstAddr: exact;", source)
        self.assertIn("actions = {", source)
        self.assertIn("default_action = drop();", source)

        self.assertIn("if (hdr.ipv4.isValid())", source)
        self.assertIn("ipv4_table.apply();", source)
        self.assertIn("} else {", source)

        self.assertIn("control MyDeparser(", source)
        self.assertIn("pkt.emit(hdr.ethernet);", source)
        self.assertIn("pkt.emit(hdr.ipv4);", source)

        # Boilerplate blocks
        self.assertIn("control MyVerifyChecksum(", source)
        self.assertIn("control MyEgress(", source)
        self.assertIn("control MyComputeChecksum(", source)
        self.assertIn("V1Switch(", source)
        self.assertIn(") main;", source)


class TestEmitEbpf(absltest.TestCase):
    def test_init_ebpf(self):
        """Compile and emit a minimal eBPF program."""

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
        def pipe(headers: Headers_t, accept):
            @p4.action
            def match(act: p4.bool):
                accept = act

            tbl = p4.table(
                key={headers.ethernet.protocol: p4.exact},
                actions=[match, p4.NoAction],
                const_entries={
                    0x0800: match(True),
                    0xD000: match(False),
                },
                implementation=ebpf_model.hash_table(64),
            )

            accept = True
            tbl.apply()

        pipeline = ebpfFilter(parser=prs, filter=pipe)
        program = compile(pipeline)
        source = emit(program)

        self.assertIn("#include <core.p4>", source)
        self.assertIn("#include <ebpf_model.p4>", source)
        self.assertIn("parser prs(packet_in p, out Headers_t headers)", source)
        self.assertIn("control pipe(inout Headers_t headers, out bool pass)", source)
        self.assertIn("bool act", source)
        self.assertIn("const entries", source)
        self.assertIn("implementation = hash_table(64)", source)
        self.assertIn("ebpfFilter(prs(), pipe()) main;", source)
        # Must NOT contain v1model artifacts.
        self.assertNotIn("v1model", source)
        self.assertNotIn("standard_metadata", source)


if __name__ == "__main__":
    absltest.main()
