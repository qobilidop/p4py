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

type bit<256> nexthop_id_t;
type bit<256> tunnel_id_t;
type bit<256> wcmp_group_id_t;
type bit<256> vrf_id_t;
type bit<256> router_interface_id_t;
type bit<9> port_id_t;
type bit<256> mirror_session_id_t;
type bit<256> cpu_queue_t;
type bit<256> unicast_queue_t;
type bit<256> multicast_queue_t;
typedef bit<6> route_metadata_t;
typedef bit<8> acl_metadata_t;
typedef bit<16> multicast_group_id_t;
typedef bit<16> replica_instance_t;
const vlan_id_t INTERNAL_VLAN_ID = 0x0fff;
const vlan_id_t NO_VLAN_ID = 0;
const vrf_id_t kDefaultVrf = 0;
typedef bit<8> ip_protocol_t;
typedef bit<32> instance_type_t;
const port_id_t SAI_P4_CPU_PORT = 0x01fe;
const ether_type_t ETHERTYPE_IPV4 = 0x0800;
const ether_type_t ETHERTYPE_IPV6 = 0x86dd;
const ether_type_t ETHERTYPE_ARP = 0x0806;
const ether_type_t ETHERTYPE_8021Q = 0x8100;
const ip_protocol_t IP_PROTOCOL_ICMP = 1;
const ip_protocol_t IP_PROTOCOL_IPV4 = 4;
const ip_protocol_t IP_PROTOCOL_TCP = 6;
const ip_protocol_t IP_PROTOCOL_UDP = 17;
const ip_protocol_t IP_PROTOCOL_IPV6 = 41;
const ip_protocol_t IP_PROTOCOL_ICMPV6 = 58;
const ip_protocol_t IP_PROTOCOL_V6_EXTENSION_HOP_BY_HOP = 0;
const instance_type_t PKT_INSTANCE_TYPE_INGRESS_CLONE = 1;
const instance_type_t PKT_INSTANCE_TYPE_EGRESS_CLONE = 2;
const instance_type_t PKT_INSTANCE_TYPE_REPLICATION = 5;

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

action set_nexthop_id(inout local_metadata_t local_metadata, nexthop_id_t nexthop_id) {
    local_metadata.nexthop_id_valid = true;
    local_metadata.nexthop_id_value = nexthop_id;
}

control packet_out_decap(headers,
                         local_metadata,
                         standard_metadata) {
    apply {
        if (headers.packet_out_header.isValid() && headers.packet_out_header.submit_to_ingress == 0) {
            standard_metadata.egress_spec = (bit<9>) headers.packet_out_header.egress_port;
            local_metadata.bypass_ingress = true;
        }
        headers.packet_out_header.setInvalid();
    }
}

control vlan_untag(headers,
                   local_metadata,
                   standard_metadata) {
    action disable_vlan_checks() {
        local_metadata.enable_vlan_checks = false;
    }

    table disable_vlan_checks_table {
        key = {
            1w1: ternary;
        }
        actions = {
            disable_vlan_checks;
        }
        size = 1;
    }

    apply {
        if (headers.vlan.isValid()) {
            local_metadata.vlan_id = headers.vlan.vlan_id;
            headers.ethernet.ether_type = headers.vlan.ether_type;
            headers.vlan.setInvalid();
            local_metadata.input_packet_is_vlan_tagged = true;
        } else {
            local_metadata.vlan_id = INTERNAL_VLAN_ID;
        }
        local_metadata.enable_vlan_checks = true;
        disable_vlan_checks_table.apply();
    }
}

control acl_pre_ingress(in headers_t headers,
                        inout local_metadata_t local_metadata,
                        in standard_metadata_t standard_metadata) {
    bit<6> dscp = 0;

    bit<2> ecn = 0;

    bit<8> ip_protocol = 0;

    bool set_outer_vlan_id_action_applied = false;

    bit<12> set_outer_vlan_id_action_vlan_id = 0;

    direct_counter(CounterType.packets_and_bytes) acl_pre_ingress_counter;

    direct_counter(CounterType.packets_and_bytes) acl_pre_ingress_vlan_counter;

    direct_counter(CounterType.packets_and_bytes) acl_pre_ingress_metadata_counter;

    action set_vrf(vrf_id_t vrf_id) {
        local_metadata.vrf_id = vrf_id;
        acl_pre_ingress_counter.count();
    }

    action set_outer_vlan_id(vlan_id_t vlan_id) {
        set_outer_vlan_id_action_applied = true;
        set_outer_vlan_id_action_vlan_id = vlan_id;
        acl_pre_ingress_vlan_counter.count();
    }

    action set_acl_metadata(acl_metadata_t acl_metadata) {
        local_metadata.acl_metadata = acl_metadata;
        acl_pre_ingress_metadata_counter.count();
    }

    action set_outer_vlan_id_and_acl_metadata(vlan_id_t vlan_id, acl_metadata_t acl_metadata) {
        set_outer_vlan_id_action_applied = true;
        set_outer_vlan_id_action_vlan_id = vlan_id;
        local_metadata.acl_metadata = acl_metadata;
        acl_pre_ingress_vlan_counter.count();
    }

    table acl_pre_ingress_table {
        key = {
            headers.ipv4.isValid() || headers.ipv6.isValid(): optional;
            headers.ipv4.isValid(): optional;
            headers.ipv6.isValid(): optional;
            headers.ethernet.src_addr: ternary;
            headers.ipv4.dst_addr: ternary;
            headers.ipv6.dst_addr[127:64]: ternary;
            dscp: ternary;
            ecn: ternary;
            local_metadata.ingress_port: optional;
        }
        actions = {
            set_vrf;
            NoAction;
        }
        default_action = NoAction();
        counters = acl_pre_ingress_counter;
    }

    table acl_pre_ingress_vlan_table {
        key = {
            headers.ipv4.isValid() || headers.ipv6.isValid(): optional;
            headers.ipv4.isValid(): optional;
            headers.ipv6.isValid(): optional;
            headers.ethernet.ether_type: ternary;
            local_metadata.vlan_id: ternary;
        }
        actions = {
            set_outer_vlan_id;
            set_outer_vlan_id_and_acl_metadata;
            NoAction;
        }
        default_action = NoAction();
        counters = acl_pre_ingress_vlan_counter;
    }

    table acl_pre_ingress_metadata_table {
        key = {
            headers.ipv4.isValid() || headers.ipv6.isValid(): optional;
            headers.ipv4.isValid(): optional;
            headers.ipv6.isValid(): optional;
            ip_protocol: ternary;
            local_metadata.l4_dst_port: ternary;
            headers.icmp.type: ternary;
            dscp: ternary;
            ecn: ternary;
            local_metadata.ingress_port: optional;
        }
        actions = {
            set_acl_metadata;
            set_outer_vlan_id;
            NoAction;
        }
        default_action = NoAction();
        counters = acl_pre_ingress_metadata_counter;
    }

    apply {
        if (headers.ipv4.isValid()) {
            dscp = headers.ipv4.dscp;
            ecn = headers.ipv4.ecn;
            ip_protocol = headers.ipv4.protocol;
        } else if (headers.ipv6.isValid()) {
            dscp = headers.ipv6.dscp;
            ecn = headers.ipv6.ecn;
            if (headers.ipv6.next_header == 0 && headers.hop_by_hop_options.isValid()) {
                ip_protocol = headers.hop_by_hop_options.next_header;
            } else {
                ip_protocol = headers.ipv6.next_header;
            }
        }
        acl_pre_ingress_vlan_table.apply();
        acl_pre_ingress_metadata_table.apply();
        acl_pre_ingress_table.apply();
        if (set_outer_vlan_id_action_applied && local_metadata.input_packet_is_vlan_tagged) {
            local_metadata.vlan_id = set_outer_vlan_id_action_vlan_id;
        }
    }
}

control ingress_vlan_checks(headers,
                            local_metadata,
                            standard_metadata) {
    bool enable_ingress_vlan_checks = true;

    bool ingress_port_is_member_of_vlan = false;

    action disable_ingress_vlan_checks() {
        enable_ingress_vlan_checks = false;
    }

    table disable_ingress_vlan_checks_table {
        key = {
            1w1: lpm;
        }
        actions = {
            disable_ingress_vlan_checks;
        }
        size = 1;
    }

    apply {
        disable_ingress_vlan_checks_table.apply();
        if (local_metadata.enable_vlan_checks && enable_ingress_vlan_checks && !ingress_port_is_member_of_vlan && !(local_metadata.vlan_id == NO_VLAN_ID || local_metadata.vlan_id == INTERNAL_VLAN_ID)) {
            local_metadata.marked_to_drop_by_ingress_vlan_checks = true;
            mark_to_drop(standard_metadata);
        }
    }
}

control admit_google_system_mac(headers,
                                local_metadata) {
    apply {
        local_metadata.admit_to_l3 = (headers.ethernet.dst_addr & 0x010000000000) == 0;
    }
}

control l3_admit(headers,
                 local_metadata,
                 standard_metadata) {
    action admit_to_l3() {
        local_metadata.admit_to_l3 = true;
    }

    table l3_admit_table {
        key = {
            headers.ethernet.dst_addr: ternary;
            local_metadata.ingress_port: optional;
        }
        actions = {
            admit_to_l3;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (local_metadata.marked_to_drop_by_ingress_vlan_checks) {
            local_metadata.admit_to_l3 = false;
        } else {
            l3_admit_table.apply();
        }
    }
}

control routing_lookup(in headers_t headers,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {
    action no_action() {
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_wcmp_group_id(wcmp_group_id_t wcmp_group_id) {
        local_metadata.wcmp_group_id_valid = true;
        local_metadata.wcmp_group_id_value = wcmp_group_id;
    }

    action set_wcmp_group_id_and_metadata(wcmp_group_id_t wcmp_group_id, route_metadata_t route_metadata) {
        set_wcmp_group_id(wcmp_group_id);
        local_metadata.route_metadata = route_metadata;
    }

    action set_metadata_and_drop(route_metadata_t route_metadata) {
        local_metadata.route_metadata = route_metadata;
        mark_to_drop(standard_metadata);
    }

    action set_nexthop_id_and_metadata(nexthop_id_t nexthop_id, route_metadata_t route_metadata) {
        local_metadata.nexthop_id_valid = true;
        local_metadata.nexthop_id_value = nexthop_id;
        local_metadata.route_metadata = route_metadata;
    }

    action set_multicast_group_id(multicast_group_id_t multicast_group_id) {
        standard_metadata.mcast_grp = multicast_group_id;
    }

    table vrf_table {
        key = {
            local_metadata.vrf_id: exact;
        }
        actions = {
            no_action;
        }
        default_action = no_action();
    }

    table ipv4_table {
        key = {
            local_metadata.vrf_id: exact;
            headers.ipv4.dst_addr: lpm;
        }
        actions = {
            drop;
            set_nexthop_id(local_metadata);
            set_wcmp_group_id;
            set_nexthop_id_and_metadata;
            set_wcmp_group_id_and_metadata;
            set_metadata_and_drop;
        }
        default_action = drop();
    }

    table ipv6_table {
        key = {
            local_metadata.vrf_id: exact;
            headers.ipv6.dst_addr: lpm;
        }
        actions = {
            drop;
            set_nexthop_id(local_metadata);
            set_wcmp_group_id;
            set_nexthop_id_and_metadata;
            set_wcmp_group_id_and_metadata;
            set_metadata_and_drop;
        }
        default_action = drop();
    }

    table ipv4_multicast_table {
        key = {
            local_metadata.vrf_id: exact;
            headers.ipv4.dst_addr: exact;
        }
        actions = {
            set_multicast_group_id;
        }
    }

    table ipv6_multicast_table {
        key = {
            local_metadata.vrf_id: exact;
            headers.ipv6.dst_addr: exact;
        }
        actions = {
            set_multicast_group_id;
        }
    }

    apply {
        mark_to_drop(standard_metadata);
        vrf_table.apply();
        if (headers.ipv4.isValid()) {
            if ((headers.ipv4.dst_addr & 4026531840) == 3758096384) {
                if (headers.ethernet.dst_addr[47:24] == 65630 && headers.ethernet.dst_addr[23:23] == 0) {
                    if (!local_metadata.marked_to_drop_by_ingress_vlan_checks) {
                        local_metadata.route_hit = ipv4_multicast_table.apply().hit;
                    }
                }
            } else if (headers.ethernet.dst_addr[40:40] == 0 && local_metadata.admit_to_l3) {
                local_metadata.route_hit = ipv4_table.apply().hit;
            }
        } else if (headers.ipv6.isValid()) {
            if ((headers.ipv6.dst_addr & 338953138925153547590470800371487866880) == 338953138925153547590470800371487866880) {
                if (headers.ethernet.dst_addr[47:32] == 13107) {
                    if (!local_metadata.marked_to_drop_by_ingress_vlan_checks) {
                        local_metadata.route_hit = ipv6_multicast_table.apply().hit;
                    }
                }
            } else if (headers.ethernet.dst_addr[40:40] == 0 && local_metadata.admit_to_l3) {
                local_metadata.route_hit = ipv6_table.apply().hit;
            }
        }
    }
}

control acl_ingress(in headers_t headers,
                    inout local_metadata_t local_metadata,
                    inout standard_metadata_t standard_metadata) {
    bit<8> ttl = 0;

    bit<6> dscp = 0;

    bit<2> ecn = 0;

    bit<8> ip_protocol = 0;

    bool cancel_copy = false;

    direct_counter(CounterType.packets_and_bytes) acl_ingress_counter;

    direct_counter(CounterType.packets_and_bytes) acl_ingress_qos_counter;

    direct_counter(CounterType.packets_and_bytes) acl_ingress_counting_counter;

    direct_counter(CounterType.packets_and_bytes) acl_ingress_security_counter;

    direct_meter<MeterColor_t>(MeterType.bytes) acl_ingress_meter;

    direct_meter<MeterColor_t>(MeterType.bytes) acl_ingress_qos_meter;

    action acl_copy(cpu_queue_t qos_queue) {
        acl_ingress_counter.count();
        local_metadata.marked_to_copy = true;
    }

    action acl_trap(cpu_queue_t qos_queue) {
        acl_copy(qos_queue);
        local_metadata.acl_drop = true;
    }

    action acl_forward() {
    }

    action acl_count() {
        acl_ingress_counting_counter.count();
    }

    action acl_mirror(mirror_session_id_t mirror_session_id) {
        acl_ingress_counter.count();
        local_metadata.marked_to_mirror = true;
        local_metadata.mirror_session_id = mirror_session_id;
    }

    action set_qos_queue_and_cancel_copy_above_rate_limit(cpu_queue_t qos_queue) {
        acl_ingress_qos_meter.read(local_metadata.color);
    }

    action set_cpu_queue_and_cancel_copy(cpu_queue_t cpu_queue) {
        cancel_copy = true;
    }

    action set_dscp_and_queues_and_deny_above_rate_limit(bit<6> dscp, cpu_queue_t cpu_queue, multicast_queue_t green_multicast_queue, multicast_queue_t red_multicast_queue, unicast_queue_t green_unicast_queue, unicast_queue_t red_unicast_queue) {
        acl_ingress_qos_meter.read(local_metadata.color);
        local_metadata.enable_dscp_rewrite = true;
        local_metadata.packet_rewrites.dscp = dscp;
    }

    action set_cpu_queue_and_deny_above_rate_limit(cpu_queue_t cpu_queue) {
        acl_ingress_qos_meter.read(local_metadata.color);
    }

    action set_cpu_queue(cpu_queue_t cpu_queue) {
    }

    action set_forwarding_queues(multicast_queue_t green_multicast_queue, multicast_queue_t red_multicast_queue, unicast_queue_t green_unicast_queue, unicast_queue_t red_unicast_queue) {
        acl_ingress_qos_meter.read(local_metadata.color);
    }

    action acl_deny() {
        cancel_copy = true;
        local_metadata.acl_drop = true;
    }

    action acl_drop() {
        local_metadata.acl_drop = true;
    }

    action redirect_to_nexthop(nexthop_id_t nexthop_id) {
        local_metadata.acl_ingress_nexthop_redirect = true;
        local_metadata.nexthop_id_valid = true;
        local_metadata.nexthop_id_value = nexthop_id;
        local_metadata.wcmp_group_id_valid = false;
        standard_metadata.mcast_grp = 0;
    }

    action redirect_to_ipmc_group(multicast_group_id_t multicast_group_id) {
        standard_metadata.mcast_grp = multicast_group_id;
        local_metadata.acl_ingress_ipmc_redirect = true;
        local_metadata.nexthop_id_valid = false;
        local_metadata.wcmp_group_id_valid = false;
    }

    action redirect_to_port(port_id_t redirect_port) {
        local_metadata.redirect_port = (bit<9>) redirect_port;
        local_metadata.redirect_port_valid = true;
        local_metadata.wcmp_group_id_valid = false;
        standard_metadata.mcast_grp = 0;
    }

    action acl_mirror_and_redirect_to_port(mirror_session_id_t mirror_session_id, port_id_t redirect_port) {
        acl_ingress_counter.count();
        local_metadata.marked_to_mirror = true;
        local_metadata.mirror_session_id = mirror_session_id;
        local_metadata.redirect_port = (bit<9>) redirect_port;
        local_metadata.redirect_port_valid = true;
        local_metadata.wcmp_group_id_valid = false;
        standard_metadata.mcast_grp = 0;
    }

    action redirect_to_l2mc_group(multicast_group_id_t multicast_group_id) {
        local_metadata.acl_ingress_l2mc_redirect = true;
        standard_metadata.mcast_grp = multicast_group_id;
        local_metadata.nexthop_id_valid = false;
        local_metadata.wcmp_group_id_valid = false;
    }

    table acl_ingress_table {
        key = {
            headers.ipv4.isValid() || headers.ipv6.isValid(): optional;
            headers.ipv4.isValid(): optional;
            headers.ipv6.isValid(): optional;
            headers.ethernet.ether_type: ternary;
            headers.ethernet.dst_addr: ternary;
            headers.ipv4.src_addr: ternary;
            headers.ipv4.dst_addr: ternary;
            headers.ipv6.src_addr[127:64]: ternary;
            headers.ipv6.dst_addr[127:64]: ternary;
            ttl: ternary;
            ip_protocol: ternary;
            headers.icmp.type: ternary;
            headers.icmp.type: ternary;
            local_metadata.l4_src_port: ternary;
            local_metadata.l4_dst_port: ternary;
            headers.arp.target_proto_addr: ternary;
            local_metadata.ingress_port: optional;
            local_metadata.route_metadata: optional;
            local_metadata.acl_metadata: ternary;
            local_metadata.vlan_id: ternary;
        }
        actions = {
            acl_copy;
            acl_trap;
            acl_forward;
            acl_mirror;
            acl_drop;
            redirect_to_l2mc_group;
            redirect_to_nexthop;
            NoAction;
        }
        default_action = NoAction();
        counters = acl_ingress_counter;
    }

    table acl_ingress_qos_table {
        key = {
            headers.ipv4.isValid() || headers.ipv6.isValid(): optional;
            headers.ipv4.isValid(): optional;
            headers.ipv6.isValid(): optional;
            headers.ethernet.ether_type: ternary;
            ttl: ternary;
            ip_protocol: ternary;
            headers.icmp.type: ternary;
            local_metadata.l4_dst_port: ternary;
            local_metadata.acl_metadata: ternary;
            local_metadata.route_metadata: ternary;
            headers.ethernet.dst_addr: ternary;
            headers.arp.target_proto_addr: ternary;
            local_metadata.ingress_port: optional;
            local_metadata.vlan_id: ternary;
        }
        actions = {
            set_qos_queue_and_cancel_copy_above_rate_limit;
            set_cpu_queue_and_deny_above_rate_limit;
            acl_forward;
            acl_drop;
            set_cpu_queue;
            set_dscp_and_queues_and_deny_above_rate_limit;
            set_forwarding_queues;
            NoAction;
        }
        default_action = NoAction();
        meters = acl_ingress_qos_meter;
        counters = acl_ingress_qos_counter;
    }

    table acl_ingress_mirror_and_redirect_table {
        key = {
            local_metadata.ingress_port: optional;
            local_metadata.acl_metadata: ternary;
            local_metadata.vlan_id: ternary;
            headers.ipv4.isValid() || headers.ipv6.isValid(): optional;
            headers.ipv4.isValid(): optional;
            headers.ipv6.isValid(): optional;
            headers.ipv4.dst_addr: ternary;
            headers.ipv6.dst_addr[127:64]: ternary;
            local_metadata.vrf_id: optional;
        }
        actions = {
            acl_mirror;
            acl_mirror_and_redirect_to_port;
            redirect_to_port;
            acl_forward;
            redirect_to_nexthop;
            redirect_to_ipmc_group;
            set_cpu_queue_and_cancel_copy;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (headers.ipv4.isValid()) {
            ttl = headers.ipv4.ttl;
            dscp = headers.ipv4.dscp;
            ecn = headers.ipv4.ecn;
            ip_protocol = headers.ipv4.protocol;
        } else if (headers.ipv6.isValid()) {
            ttl = headers.ipv6.hop_limit;
            dscp = headers.ipv6.dscp;
            ecn = headers.ipv6.ecn;
            ip_protocol = headers.ipv6.next_header;
        }
        acl_ingress_table.apply();
        acl_ingress_qos_table.apply();
        acl_ingress_mirror_and_redirect_table.apply();
        if (cancel_copy) {
            local_metadata.marked_to_copy = false;
        }
    }
}

control routing_resolution(in headers_t headers,
                           inout local_metadata_t local_metadata,
                           inout standard_metadata_t standard_metadata) {
    bool tunnel_id_valid = false;

    bit<256> tunnel_id_value = 0;

    bool router_interface_id_valid = false;

    bit<256> router_interface_id_value = 0;

    bool neighbor_id_valid = false;

    bit<128> neighbor_id_value = 0;

    action_selector(HashAlgorithm.identity,
                    31296,
                    16) wcmp_group_selector;

    action set_dst_mac(ethernet_addr_t dst_mac) {
        local_metadata.packet_rewrites.dst_mac = dst_mac;
    }

    action unicast_set_port_and_src_mac_and_vlan_id(port_id_t port, ethernet_addr_t src_mac, vlan_id_t vlan_id) {
        standard_metadata.egress_spec = (bit<9>) port;
        local_metadata.packet_rewrites.src_mac = src_mac;
        local_metadata.packet_rewrites.vlan_id = vlan_id;
    }

    action set_port_and_src_mac(port_id_t port, ethernet_addr_t src_mac) {
        unicast_set_port_and_src_mac_and_vlan_id(port, src_mac, INTERNAL_VLAN_ID);
    }

    action unicast_set_port_and_src_mac(port_id_t port, ethernet_addr_t src_mac) {
        unicast_set_port_and_src_mac_and_vlan_id(port, src_mac, INTERNAL_VLAN_ID);
    }

    action set_ip_nexthop_and_disable_rewrites(router_interface_id_t router_interface_id, ipv6_addr_t neighbor_id, bit<1> disable_decrement_ttl, bit<1> disable_src_mac_rewrite, bit<1> disable_dst_mac_rewrite, bit<1> disable_vlan_rewrite) {
        router_interface_id_valid = true;
        router_interface_id_value = router_interface_id;
        neighbor_id_valid = true;
        neighbor_id_value = neighbor_id;
        local_metadata.enable_decrement_ttl = !(bool) disable_decrement_ttl;
        local_metadata.enable_src_mac_rewrite = !(bool) disable_src_mac_rewrite;
        local_metadata.enable_dst_mac_rewrite = !(bool) disable_dst_mac_rewrite;
        local_metadata.enable_vlan_rewrite = !(bool) disable_vlan_rewrite;
    }

    action set_ip_nexthop(router_interface_id_t router_interface_id, ipv6_addr_t neighbor_id) {
        set_ip_nexthop_and_disable_rewrites(router_interface_id, neighbor_id, 0, 0, 0, 0);
    }

    action set_p2p_tunnel_encap_nexthop(tunnel_id_t tunnel_id) {
        tunnel_id_valid = true;
        tunnel_id_value = tunnel_id;
    }

    action mark_for_p2p_tunnel_encap(ipv6_addr_t encap_src_ip, ipv6_addr_t encap_dst_ip, router_interface_id_t router_interface_id) {
        local_metadata.tunnel_encap_src_ipv6 = encap_src_ip;
        local_metadata.tunnel_encap_dst_ipv6 = encap_dst_ip;
        local_metadata.apply_tunnel_encap_at_egress = true;
        set_ip_nexthop(router_interface_id, encap_dst_ip);
    }

    table neighbor_table {
        key = {
            router_interface_id_value: exact;
            neighbor_id_value: exact;
        }
        actions = {
            set_dst_mac;
            NoAction;
        }
        default_action = NoAction();
    }

    table router_interface_table {
        key = {
            router_interface_id_value: exact;
        }
        actions = {
            set_port_and_src_mac;
            unicast_set_port_and_src_mac_and_vlan_id;
            unicast_set_port_and_src_mac;
            NoAction;
        }
        default_action = NoAction();
    }

    table nexthop_table {
        key = {
            local_metadata.nexthop_id_value: exact;
        }
        actions = {
            set_ip_nexthop;
            set_p2p_tunnel_encap_nexthop;
            set_ip_nexthop_and_disable_rewrites;
            NoAction;
        }
        default_action = NoAction();
    }

    table tunnel_table {
        key = {
            tunnel_id_value: exact;
        }
        actions = {
            mark_for_p2p_tunnel_encap;
            NoAction;
        }
        default_action = NoAction();
    }

    table wcmp_group_table {
        key = {
            local_metadata.wcmp_group_id_value: exact;
            local_metadata.wcmp_selector_input: selector;
        }
        actions = {
            set_nexthop_id(local_metadata);
            NoAction;
        }
        implementation = wcmp_group_selector;
        default_action = NoAction();
    }

    apply {
        if (local_metadata.wcmp_group_id_valid) {
            wcmp_group_table.apply();
        }
        if (local_metadata.nexthop_id_valid) {
            nexthop_table.apply();
            if (tunnel_id_valid) {
                tunnel_table.apply();
            }
            if (router_interface_id_valid && neighbor_id_valid) {
                router_interface_table.apply();
                neighbor_table.apply();
            }
        }
        if (local_metadata.redirect_port_valid) {
            standard_metadata.egress_spec = local_metadata.redirect_port;
        }
        local_metadata.packet_in_target_egress_port = standard_metadata.egress_spec;
        local_metadata.packet_in_ingress_port = standard_metadata.ingress_port;
        if (local_metadata.acl_drop) {
            mark_to_drop(standard_metadata);
        }
    }
}

control egress_vlan_checks(headers,
                           local_metadata,
                           standard_metadata) {
    bit<9> port = 0;

    bool egress_port_is_member_of_vlan = false;

    bool enable_egress_vlan_checks = true;

    action disable_egress_vlan_checks() {
        enable_egress_vlan_checks = false;
    }

    action no_action() {
    }

    action make_tagged_member() {
        egress_port_is_member_of_vlan = true;
    }

    action make_untagged_member() {
        egress_port_is_member_of_vlan = true;
        local_metadata.omit_vlan_tag_on_egress_packet = true;
    }

    table disable_egress_vlan_checks_table {
        key = {
            1w1: lpm;
        }
        actions = {
            disable_egress_vlan_checks;
        }
        size = 1;
    }

    table vlan_table {
        key = {
            local_metadata.vlan_id: exact;
        }
        actions = {
            no_action;
        }
    }

    table vlan_membership_table {
        key = {
            local_metadata.vlan_id: exact;
            port: exact;
        }
        actions = {
            make_tagged_member;
            make_untagged_member;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        disable_egress_vlan_checks_table.apply();
        vlan_table.apply();
        if (!(standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) && !(standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE)) {
            vlan_membership_table.apply();
            if (local_metadata.enable_vlan_checks && enable_egress_vlan_checks && !egress_port_is_member_of_vlan && !(local_metadata.vlan_id == NO_VLAN_ID || local_metadata.vlan_id == INTERNAL_VLAN_ID)) {
                mark_to_drop(standard_metadata);
            }
        }
    }
}

control vlan_tag(headers,
                 local_metadata,
                 standard_metadata) {
    apply {
        if (!(local_metadata.vlan_id == NO_VLAN_ID || local_metadata.vlan_id == INTERNAL_VLAN_ID) && !(standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE) && !local_metadata.omit_vlan_tag_on_egress_packet) {
            headers.vlan.setValid();
            headers.vlan.priority_code_point = 0;
            headers.vlan.drop_eligible_indicator = 0;
            headers.vlan.vlan_id = local_metadata.vlan_id;
            headers.vlan.ether_type = headers.ethernet.ether_type;
            headers.ethernet.ether_type = ETHERTYPE_8021Q;
        }
    }
}

parser packet_parser(packet_in packet,
                out headers_t headers,
                inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {
    state start {
        local_metadata.enable_vlan_checks = false;
        local_metadata.marked_to_drop_by_ingress_vlan_checks = false;
        local_metadata.vlan_id = 0;
        local_metadata.input_packet_is_vlan_tagged = false;
        local_metadata.omit_vlan_tag_on_egress_packet = false;
        local_metadata.admit_to_l3 = false;
        local_metadata.vrf_id = kDefaultVrf;
        local_metadata.enable_decrement_ttl = false;
        local_metadata.enable_src_mac_rewrite = false;
        local_metadata.enable_dst_mac_rewrite = false;
        local_metadata.enable_vlan_rewrite = false;
        local_metadata.enable_dscp_rewrite = false;
        local_metadata.packet_rewrites.src_mac = 0;
        local_metadata.packet_rewrites.dst_mac = 0;
        local_metadata.packet_rewrites.dscp = 0;
        local_metadata.l4_src_port = 0;
        local_metadata.l4_dst_port = 0;
        local_metadata.wcmp_selector_input = 0;
        local_metadata.apply_tunnel_decap_at_end_of_pre_ingress = false;
        local_metadata.apply_tunnel_encap_at_egress = false;
        local_metadata.tunnel_encap_src_ipv6 = 0;
        local_metadata.tunnel_encap_dst_ipv6 = 0;
        local_metadata.marked_to_copy = false;
        local_metadata.marked_to_mirror = false;
        local_metadata.mirror_session_id = 0;
        local_metadata.mirror_egress_port = 0;
        local_metadata.color = MeterColor_t.GREEN;
        local_metadata.ingress_port = (port_id_t) standard_metadata.ingress_port;
        local_metadata.route_metadata = 0;
        local_metadata.bypass_ingress = false;
        local_metadata.bypass_egress = false;
        local_metadata.wcmp_group_id_valid = false;
        local_metadata.wcmp_group_id_value = 0;
        local_metadata.nexthop_id_valid = false;
        local_metadata.acl_ingress_l2mc_redirect = false;
        local_metadata.nexthop_id_value = 0;
        local_metadata.route_hit = false;
        local_metadata.acl_drop = false;
        local_metadata.tunnel_termination_table_hit = false;
        local_metadata.acl_ingress_ipmc_redirect = false;
        local_metadata.redirect_port_valid = false;
        local_metadata.redirect_port = 0;
        local_metadata.acl_ingress_nexthop_redirect = false;
        transition select(standard_metadata.ingress_port) {
            SAI_P4_CPU_PORT: parse_packet_out_header;
            default: parse_ethernet;
        }
    }
    state parse_packet_out_header {
        packet.extract(headers.packet_out_header);
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(headers.ethernet);
        transition select(headers.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(headers.ipv4);
        transition select(headers.ipv4.protocol) {
            IP_PROTOCOL_IPV4: parse_ipv4_in_ip;
            IP_PROTOCOL_IPV6: parse_ipv6_in_ip;
            IP_PROTOCOL_ICMP: parse_icmp;
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_ipv4_in_ip {
        packet.extract(headers.inner_ipv4);
        transition select(headers.inner_ipv4.protocol) {
            IP_PROTOCOL_ICMP: parse_icmp;
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_ipv6 {
        packet.extract(headers.ipv6);
        transition select(headers.ipv6.next_header) {
            IP_PROTOCOL_V6_EXTENSION_HOP_BY_HOP: parse_hop_by_hop_options;
            IP_PROTOCOL_IPV4: parse_ipv4_in_ip;
            IP_PROTOCOL_IPV6: parse_ipv6_in_ip;
            IP_PROTOCOL_ICMPV6: parse_icmp;
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_hop_by_hop_options {
        packet.extract(headers.hop_by_hop_options);
        transition select(headers.hop_by_hop_options.header_extension_length) {
            0: next_header_for_hop_by_hop_options;
            default: accept;
        }
    }
    state next_header_for_hop_by_hop_options {
        transition select(headers.hop_by_hop_options.next_header) {
            IP_PROTOCOL_IPV4: parse_ipv4_in_ip;
            IP_PROTOCOL_IPV6: parse_ipv6_in_ip;
            IP_PROTOCOL_ICMPV6: parse_icmp;
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_ipv6_in_ip {
        packet.extract(headers.inner_ipv6);
        transition select(headers.inner_ipv6.next_header) {
            IP_PROTOCOL_V6_EXTENSION_HOP_BY_HOP: parse_hop_by_hop_options_in_ip;
            IP_PROTOCOL_ICMPV6: parse_icmp;
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_hop_by_hop_options_in_ip {
        packet.extract(headers.inner_hop_by_hop_options);
        transition select(headers.inner_hop_by_hop_options.header_extension_length) {
            0: next_header_for_hop_by_hop_options_in_ip;
            default: accept;
        }
    }
    state next_header_for_hop_by_hop_options_in_ip {
        transition select(headers.inner_hop_by_hop_options.next_header) {
            IP_PROTOCOL_ICMPV6: parse_icmp;
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(headers.tcp);
        local_metadata.l4_src_port = headers.tcp.src_port;
        local_metadata.l4_dst_port = headers.tcp.dst_port;
        transition accept;
    }
    state parse_udp {
        packet.extract(headers.udp);
        local_metadata.l4_src_port = headers.udp.src_port;
        local_metadata.l4_dst_port = headers.udp.dst_port;
        transition accept;
    }
    state parse_icmp {
        packet.extract(headers.icmp);
        transition accept;
    }
    state parse_arp {
        packet.extract(headers.arp);
        transition accept;
    }
}

control verify_ipv4_checksum(inout headers_t headers, inout local_metadata_t local_metadata) {
    apply {
        verify_checksum(
            headers.ipv4.isValid(),
            { headers.ipv4.version, headers.ipv4.ihl, headers.ipv4.dscp, headers.ipv4.ecn, headers.ipv4.total_len, headers.ipv4.identification, headers.ipv4.reserved, headers.ipv4.do_not_fragment, headers.ipv4.more_fragments, headers.ipv4.frag_offset, headers.ipv4.ttl, headers.ipv4.protocol, headers.ipv4.src_addr, headers.ipv4.dst_addr },
            headers.ipv4.header_checksum,
            HashAlgorithm.csum16);
    }
}

control ingress(inout headers_t headers,
                  inout local_metadata_t local_metadata,
                  inout standard_metadata_t standard_metadata) {
    apply {
        packet_out_decap.apply(headers, local_metadata, standard_metadata);
        if (!local_metadata.bypass_ingress) {
            vlan_untag.apply(headers, local_metadata, standard_metadata);
            acl_pre_ingress.apply(headers, local_metadata, standard_metadata);
            ingress_vlan_checks.apply(headers, local_metadata, standard_metadata);
            admit_google_system_mac.apply(headers, local_metadata);
            l3_admit.apply(headers, local_metadata, standard_metadata);
            routing_lookup.apply(headers, local_metadata, standard_metadata);
            acl_ingress.apply(headers, local_metadata, standard_metadata);
            routing_resolution.apply(headers, local_metadata, standard_metadata);
        }
    }
}

control egress(inout headers_t headers,
                  inout local_metadata_t local_metadata,
                  inout standard_metadata_t standard_metadata) {
    apply {
        if (!local_metadata.bypass_egress) {
            egress_vlan_checks.apply(headers, local_metadata, standard_metadata);
            vlan_tag.apply(headers, local_metadata, standard_metadata);
        }
    }
}

control compute_ipv4_checksum(inout headers_t headers, inout local_metadata_t local_metadata) {
    apply {
        update_checksum(
            headers.ipv4.isValid(),
            { headers.ipv4.version, headers.ipv4.ihl, headers.ipv4.dscp, headers.ipv4.ecn, headers.ipv4.total_len, headers.ipv4.identification, headers.ipv4.reserved, headers.ipv4.do_not_fragment, headers.ipv4.more_fragments, headers.ipv4.frag_offset, headers.ipv4.ttl, headers.ipv4.protocol, headers.ipv4.src_addr, headers.ipv4.dst_addr },
            headers.ipv4.header_checksum,
            HashAlgorithm.csum16);
    }
}

control packet_deparser(packet_out packet, in headers_t headers) {
    apply {
        packet.emit(headers.packet_out_header);
        packet.emit(headers.packet_in_header);
        packet.emit(headers.mirror_encap_ethernet);
        packet.emit(headers.mirror_encap_vlan);
        packet.emit(headers.mirror_encap_ipv6);
        packet.emit(headers.mirror_encap_udp);
        packet.emit(headers.mirror_encap_ipfix);
        packet.emit(headers.mirror_encap_psamp_extended);
        packet.emit(headers.ethernet);
        packet.emit(headers.tunnel_encap_ipv6);
        packet.emit(headers.tunnel_encap_gre);
        packet.emit(headers.ipv4);
        packet.emit(headers.ipv6);
        packet.emit(headers.hop_by_hop_options);
        packet.emit(headers.inner_ipv4);
        packet.emit(headers.inner_ipv6);
        packet.emit(headers.inner_hop_by_hop_options);
        packet.emit(headers.arp);
        packet.emit(headers.icmp);
        packet.emit(headers.tcp);
        packet.emit(headers.udp);
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
