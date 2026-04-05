#include <core.p4>
#include <v1model.p4>

typedef bit<48> ethernet_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;
typedef bit<16> ether_type_t;
enum bit<8> PreservedFieldList {
    MIRROR_AND_PACKET_IN_COPY = 1
};

enum bit<2> MeterColor_t {
    GREEN = 0,
    YELLOW = 1,
    RED = 2
};

@p4runtime_translation("", string)
type bit<256> nexthop_id_t;
@p4runtime_translation("", string)
type bit<256> tunnel_id_t;
@p4runtime_translation("", string)
type bit<256> wcmp_group_id_t;
@p4runtime_translation("", string)
type bit<256> vrf_id_t;
@p4runtime_translation("", string)
type bit<256> router_interface_id_t;
@p4runtime_translation("", string)
type bit<9> port_id_t;
@p4runtime_translation("", string)
type bit<256> mirror_session_id_t;
@p4runtime_translation("", string)
type bit<256> cpu_queue_t;
@p4runtime_translation("", string)
type bit<256> unicast_queue_t;
@p4runtime_translation("", string)
type bit<256> multicast_queue_t;
typedef bit<6> route_metadata_t;
typedef bit<8> acl_metadata_t;
typedef bit<16> multicast_group_id_t;
typedef bit<16> replica_instance_t;
const vlan_id_t INTERNAL_VLAN_ID = 0x0fff;
const vlan_id_t NO_VLAN_ID = 0;
const vrf_id_t kDefaultVrf = 0;

header packet_in_header_t {
    port_id_t ingress_port;
    port_id_t target_egress_port;
    bit<6> unused_pad;
}

header packet_out_header_t {
    port_id_t egress_port;
    bit<1> submit_to_ingress;
    bit<6> unused_pad;
}

header ethernet_t {
    ethernet_addr_t dst_addr;
    ethernet_addr_t src_addr;
    ether_type_t ether_type;
}

header vlan_t {
    bit<3> priority_code_point;
    bit<1> drop_eligible_indicator;
    vlan_id_t vlan_id;
    ether_type_t ether_type;
}

header ipv6_t {
    bit<4> version;
    bit<6> dscp;
    bit<2> ecn;
    bit<20> flow_label;
    bit<16> payload_length;
    bit<8> next_header;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header ipfix_t {
    bit<16> version_number;
    bit<16> length;
    bit<32> export_time;
    bit<32> sequence_number;
    bit<32> observation_domain_id;
}

header psamp_extended_t {
    bit<16> template_id;
    bit<16> length;
    bit<64> observation_time;
    bit<16> flowset;
    bit<16> next_hop_index;
    bit<16> epoch;
    bit<16> ingress_port;
    bit<16> egress_port;
    bit<16> user_meta_field;
    bit<8> dlb_id;
    bit<8> variable_length;
    bit<16> packet_sampled_length;
}

header gre_t {
    bit<1> checksum_present;
    bit<1> routing_present;
    bit<1> key_present;
    bit<1> sequence_present;
    bit<1> strict_source_route;
    bit<3> recursion_control;
    bit<1> acknowledgement_present;
    bit<4> flags;
    bit<3> version;
    bit<16> protocol;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<1> reserved;
    bit<1> do_not_fragment;
    bit<1> more_fragments;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> header_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header hop_by_hop_options_t {
    bit<8> next_header;
    bit<8> header_extension_length;
    bit<48> options_and_padding;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    bit<32> rest_of_header;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header arp_t {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    bit<48> sender_hw_addr;
    bit<32> sender_proto_addr;
    bit<48> target_hw_addr;
    bit<32> target_proto_addr;
}

struct headers_t {
    packet_in_header_t packet_in_header;
    packet_out_header_t packet_out_header;
    ethernet_t mirror_encap_ethernet;
    vlan_t mirror_encap_vlan;
    ipv6_t mirror_encap_ipv6;
    udp_t mirror_encap_udp;
    ipfix_t mirror_encap_ipfix;
    psamp_extended_t mirror_encap_psamp_extended;
    ethernet_t ethernet;
    vlan_t vlan;
    ipv6_t tunnel_encap_ipv6;
    gre_t tunnel_encap_gre;
    ipv4_t ipv4;
    ipv6_t ipv6;
    hop_by_hop_options_t hop_by_hop_options;
    ipv4_t inner_ipv4;
    ipv6_t inner_ipv6;
    hop_by_hop_options_t inner_hop_by_hop_options;
    icmp_t icmp;
    tcp_t tcp;
    udp_t udp;
    arp_t arp;
}

struct packet_rewrites_t {
    ethernet_addr_t src_mac;
    ethernet_addr_t dst_mac;
    vlan_id_t vlan_id;
    bit<6> dscp;
}

struct local_metadata_t {
    bool enable_vlan_checks;
    bool marked_to_drop_by_ingress_vlan_checks;
    bool omit_vlan_tag_on_egress_packet;
    vlan_id_t vlan_id;
    bool input_packet_is_vlan_tagged;
    bool admit_to_l3;
    vrf_id_t vrf_id;
    bool enable_decrement_ttl;
    bool enable_src_mac_rewrite;
    bool enable_dst_mac_rewrite;
    bool enable_vlan_rewrite;
    bool enable_dscp_rewrite;
    packet_rewrites_t packet_rewrites;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<16> wcmp_selector_input;
    bool apply_tunnel_decap_at_end_of_pre_ingress;
    bool apply_tunnel_encap_at_egress;
    ipv6_addr_t tunnel_encap_src_ipv6;
    ipv6_addr_t tunnel_encap_dst_ipv6;
    bool marked_to_copy;
    bool marked_to_mirror;
    mirror_session_id_t mirror_session_id;
    port_id_t mirror_egress_port;
    ethernet_addr_t mirror_encap_src_mac;
    ethernet_addr_t mirror_encap_dst_mac;
    vlan_id_t mirror_encap_vlan_id;
    ipv6_addr_t mirror_encap_src_ip;
    ipv6_addr_t mirror_encap_dst_ip;
    bit<16> mirror_encap_udp_src_port;
    bit<16> mirror_encap_udp_dst_port;
    bit<9> packet_in_ingress_port;
    bit<9> packet_in_target_egress_port;
    bool redirect_port_valid;
    bit<9> redirect_port;
    MeterColor_t color;
    port_id_t ingress_port;
    route_metadata_t route_metadata;
    acl_metadata_t acl_metadata;
    bool bypass_ingress;
    bool bypass_egress;
    bool wcmp_group_id_valid;
    wcmp_group_id_t wcmp_group_id_value;
    bool nexthop_id_valid;
    nexthop_id_t nexthop_id_value;
    bool route_hit;
    bool tunnel_termination_table_hit;
    bool acl_ingress_ipmc_redirect;
    bool acl_ingress_l2mc_redirect;
    bool acl_ingress_nexthop_redirect;
    bool acl_drop;
}

control acl_wbb_ingress(in headers_t headers,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    bit<8> ttl = 0;

    direct_counter(CounterType.packets_and_bytes) acl_wbb_ingress_counter;

    direct_meter<MeterColor_t>(MeterType.bytes) acl_wbb_ingress_meter;

    action acl_wbb_ingress_copy() {
        acl_wbb_ingress_meter.read(local_metadata.color);
        clone(CloneType.I2E, 255);
        acl_wbb_ingress_counter.count();
    }

    action acl_wbb_ingress_trap() {
        acl_wbb_ingress_meter.read(local_metadata.color);
        clone(CloneType.I2E, 255);
        mark_to_drop(standard_metadata);
        acl_wbb_ingress_counter.count();
    }

    table acl_wbb_ingress_table {
        key = {
            headers.ipv4.isValid(): optional;
            headers.ipv6.isValid(): optional;
            headers.ethernet.ether_type: ternary;
            ttl: ternary;
        }
        actions = {
            acl_wbb_ingress_copy;
            acl_wbb_ingress_trap;
            NoAction;
        }
        default_action = NoAction();
        meters = acl_wbb_ingress_meter;
        counters = acl_wbb_ingress_counter;
        size = 8;
    }

    apply {
        if (headers.ipv4.isValid()) {
            ttl = headers.ipv4.ttl;
        } else if (headers.ipv6.isValid()) {
            ttl = headers.ipv6.hop_limit;
        }
        acl_wbb_ingress_table.apply();
    }
}

parser packet_parser(packet_in packet,
                out headers_t headers,
                inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition accept;
    }
}

control verify_ipv4_checksum(inout headers_t headers, inout local_metadata_t local_metadata) {
    apply {
    }
}

control ingress(inout headers_t headers,
                  inout local_metadata_t local_metadata,
                  inout standard_metadata_t standard_metadata) {
    apply {
        acl_wbb_ingress.apply(headers, local_metadata, standard_metadata);
    }
}

control egress(inout headers_t headers,
                  inout local_metadata_t local_metadata,
                  inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control compute_ipv4_checksum(inout headers_t headers, inout local_metadata_t local_metadata) {
    apply {
    }
}

control packet_deparser(packet_out packet, in headers_t headers) {
    apply {
    }
}

V1Switch(
    packet_parser(),
    verify_ipv4_checksum(),
    ingress(),
    egress(),
    compute_ipv4_checksum(),
    packet_deparser()
) main;
