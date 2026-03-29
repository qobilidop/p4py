#include <core.p4>
#include <v1model.p4>

header hdr {
    bit<8> e;
    bit<16> t;
    bit<8> l;
    bit<8> r;
    bit<8> v;
}

struct Header_t {
    hdr h;
}

struct Meta_t {
}

parser p(packet_in b,
                out Header_t h,
                inout Meta_t m,
                inout standard_metadata_t sm) {
    state start {
        b.extract(h.h);
        transition accept;
    }
}

control MyVerifyChecksum(inout Header_t hdr, inout Meta_t meta) {
    apply {}
}

control ingress(inout Header_t h,
                  inout Meta_t m,
                  inout standard_metadata_t standard_meta) {
    action a() {
        standard_meta.egress_spec = 0;
    }

    action a_with_control_params(bit<9> x) {
        standard_meta.egress_spec = x;
    }

    table t_lpm {
        key = {
            h.h.l: lpm;
        }
        actions = {
            a;
            a_with_control_params;
        }
        const entries = {
            (0x11 &&& 0xf0) : a_with_control_params(11);
            (0x12) : a_with_control_params(12);
            (_) : a_with_control_params(13);
        }
        default_action = a();
    }

    apply {
        t_lpm.apply();
    }
}

control MyEgress(inout Header_t hdr,
                  inout Meta_t meta,
                  inout standard_metadata_t std_meta) {
    apply {}
}

control MyComputeChecksum(inout Header_t hdr, inout Meta_t meta) {
    apply {}
}

control deparser(packet_out b, in Header_t h) {
    apply {
        pkt.emit(h.h);
    }
}

V1Switch(
    p(),
    MyVerifyChecksum(),
    ingress(),
    MyEgress(),
    MyComputeChecksum(),
    deparser()
) main;
