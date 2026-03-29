"""P4Py translation of sai_p4/fixed/headers.p4."""

import p4py.lang as p4

# -- Typedefs --

ethernet_addr_t = p4.typedef(p4.bit(48), "ethernet_addr_t")
ipv4_addr_t = p4.typedef(p4.bit(32), "ipv4_addr_t")
ipv6_addr_t = p4.typedef(p4.bit(128), "ipv6_addr_t")
vlan_id_t = p4.typedef(p4.bit(12), "vlan_id_t")
ether_type_t = p4.typedef(p4.bit(16), "ether_type_t")

# -- Consts --

INTERNAL_VLAN_ID = p4.const(vlan_id_t, 0xFFF, "INTERNAL_VLAN_ID")
NO_VLAN_ID = p4.const(vlan_id_t, 0x000, "NO_VLAN_ID")

# -- Protocol headers --


class ethernet_t(p4.header):
    dst_addr: ethernet_addr_t
    src_addr: ethernet_addr_t
    ether_type: ether_type_t


class vlan_t(p4.header):
    priority_code_point: p4.bit(3)
    drop_eligible_indicator: p4.bit(1)
    vlan_id: vlan_id_t
    ether_type: ether_type_t


class ipv4_t(p4.header):
    version: p4.bit(4)
    ihl: p4.bit(4)
    dscp: p4.bit(6)
    ecn: p4.bit(2)
    total_len: p4.bit(16)
    identification: p4.bit(16)
    reserved: p4.bit(1)
    do_not_fragment: p4.bit(1)
    more_fragments: p4.bit(1)
    frag_offset: p4.bit(13)
    ttl: p4.bit(8)
    protocol: p4.bit(8)
    header_checksum: p4.bit(16)
    src_addr: ipv4_addr_t
    dst_addr: ipv4_addr_t


class ipv6_t(p4.header):
    version: p4.bit(4)
    dscp: p4.bit(6)
    ecn: p4.bit(2)
    flow_label: p4.bit(20)
    payload_length: p4.bit(16)
    next_header: p4.bit(8)
    hop_limit: p4.bit(8)
    src_addr: ipv6_addr_t
    dst_addr: ipv6_addr_t


class hop_by_hop_options_t(p4.header):
    next_header: p4.bit(8)
    header_extension_length: p4.bit(8)
    options_and_padding: p4.bit(48)


class udp_t(p4.header):
    src_port: p4.bit(16)
    dst_port: p4.bit(16)
    hdr_length: p4.bit(16)
    checksum: p4.bit(16)


class tcp_t(p4.header):
    src_port: p4.bit(16)
    dst_port: p4.bit(16)
    seq_no: p4.bit(32)
    ack_no: p4.bit(32)
    data_offset: p4.bit(4)
    res: p4.bit(4)
    flags: p4.bit(8)
    window: p4.bit(16)
    checksum: p4.bit(16)
    urgent_ptr: p4.bit(16)


class icmp_t(p4.header):
    type: p4.bit(8)
    code: p4.bit(8)
    checksum: p4.bit(16)
    rest_of_header: p4.bit(32)


class arp_t(p4.header):
    hw_type: p4.bit(16)
    proto_type: p4.bit(16)
    hw_addr_len: p4.bit(8)
    proto_addr_len: p4.bit(8)
    opcode: p4.bit(16)
    sender_hw_addr: p4.bit(48)
    sender_proto_addr: p4.bit(32)
    target_hw_addr: p4.bit(48)
    target_proto_addr: p4.bit(32)


class gre_t(p4.header):
    checksum_present: p4.bit(1)
    routing_present: p4.bit(1)
    key_present: p4.bit(1)
    sequence_present: p4.bit(1)
    strict_source_route: p4.bit(1)
    recursion_control: p4.bit(3)
    acknowledgement_present: p4.bit(1)
    flags: p4.bit(4)
    version: p4.bit(3)
    protocol: p4.bit(16)


class ipfix_t(p4.header):
    version_number: p4.bit(16)
    length: p4.bit(16)
    export_time: p4.bit(32)
    sequence_number: p4.bit(32)
    observation_domain_id: p4.bit(32)


class psamp_extended_t(p4.header):
    template_id: p4.bit(16)
    length: p4.bit(16)
    observation_time: p4.bit(64)
    flowset: p4.bit(16)
    next_hop_index: p4.bit(16)
    epoch: p4.bit(16)
    ingress_port: p4.bit(16)
    egress_port: p4.bit(16)
    user_meta_field: p4.bit(16)
    dlb_id: p4.bit(8)
    variable_length: p4.bit(8)
    packet_sampled_length: p4.bit(16)
