#include <core.p4>
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
}

struct metadata_t {
    bit<16> nexthop_index;
    bit<16> bd;
    bit<12> vrf;
}

parser ParserImpl(packet_in pkt,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t std_meta) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control verifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control ingress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t std_meta) {
    action on_miss() {
    }

    action set_bd(bit<16> bd) {
        meta.bd = bd;
    }

    action set_vrf(bit<12> vrf) {
        meta.vrf = vrf;
    }

    action fib_hit_nexthop(bit<16> nexthop_index) {
        meta.nexthop_index = nexthop_index;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_egress_details(bit<9> egress_spec) {
        std_meta.egress_spec = egress_spec;
    }

    table port_mapping {
        key = {
            std_meta.ingress_port: exact;
        }
        actions = {
            on_miss;
            set_bd;
        }
        default_action = on_miss();
    }

    table bd_table {
        key = {
            meta.bd: exact;
        }
        actions = {
            on_miss;
            set_vrf;
        }
        default_action = on_miss();
    }

    table ipv4_fib {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            on_miss;
            fib_hit_nexthop;
        }
        default_action = on_miss();
    }

    table ipv4_fib_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            on_miss;
            fib_hit_nexthop;
        }
        default_action = on_miss();
    }

    table nexthop {
        key = {
            meta.nexthop_index: exact;
        }
        actions = {
            on_miss;
            set_egress_details;
        }
        default_action = on_miss();
    }

    apply {
        port_mapping.apply();
        bd_table.apply();
        if (hdr.ipv4.isValid()) {
            switch (ipv4_fib.apply().action_run) {
                on_miss: {
                    ipv4_fib_lpm.apply();
                }
            }
            nexthop.apply();
        }
    }
}

control egress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t std_meta) {
    action on_miss() {
    }

    action rewrite_mac(bit<48> smac, bit<48> dmac) {
        hdr.ethernet.srcAddr = smac;
        hdr.ethernet.dstAddr = dmac;
    }

    table rewrite_mac_table {
        key = {
            meta.nexthop_index: exact;
        }
        actions = {
            on_miss;
            rewrite_mac;
        }
        default_action = on_miss();
    }

    apply {
        rewrite_mac_table.apply();
    }
}

control computeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control DeparserImpl(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

V1Switch(
    ParserImpl(),
    verifyChecksum(),
    ingress(),
    egress(),
    computeChecksum(),
    DeparserImpl()
) main;
