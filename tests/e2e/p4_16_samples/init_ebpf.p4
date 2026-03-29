#include <core.p4>
#include <ebpf_model.p4>

header Ethernet {
    bit<48> destination;
    bit<48> source;
    bit<16> protocol;
}

struct Headers_t {
    Ethernet ethernet;
}

parser prs(packet_in p, out Headers_t headers) {
    state start {
        p.extract(headers.ethernet);
        transition accept;
    }
}

control pipe(inout Headers_t headers, out bool accept) {
    action match(bool act) {
        accept = act;
    }

    table tbl {
        key = {
            headers.ethernet.protocol: exact;
        }
        actions = {
            match;
            NoAction;
        }
        const entries = {
            (2048) : match(true);
            (53248) : match(false);
        }
        implementation = hash_table(64);
    }

    apply {
        accept = true;
        tbl.apply();
    }
}

ebpfFilter(prs(), pipe()) main;
