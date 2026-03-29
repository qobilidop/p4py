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

parser p_(packet_in pkt,
                out Header_t hdr,
                inout Meta_t meta,
                inout standard_metadata_t std_meta) {
    state start {
        pkt.extract(hdr.h);
        transition accept;
    }
}

control MyVerifyChecksum(inout Header_t hdr, inout Meta_t meta) {
    apply {}
}

control ingress(inout Header_t hdr,
                  inout Meta_t meta,
                  inout standard_metadata_t std_meta) {
    action a() {
        std_meta.egress_spec = 9w0;
    }

    action a_with_control_params(bit<9> x) {
        std_meta.egress_spec = x;
    }

    table t_lpm {
        key = {
            hdr.h.l: lpm;
        }
        actions = {
            a;
            a_with_control_params;
        }
        const entries = {
            (17 &&& 240) : a_with_control_params(11);
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

control deparser(packet_out pkt, in Header_t hdr) {
    apply {
        pkt.emit(hdr.h);
    }
}

V1Switch(
    p_(),
    MyVerifyChecksum(),
    ingress(),
    MyEgress(),
    MyComputeChecksum(),
    deparser()
) main;
