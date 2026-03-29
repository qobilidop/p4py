"""P4Py translation of sai_p4/fixed/metadata.p4 (PLATFORM_BMV2)."""

import p4py.lang as p4

from tests.e2e.sai_p4.fixed.headers import (
    arp_t,
    ethernet_addr_t,
    ethernet_t,
    gre_t,
    hop_by_hop_options_t,
    icmp_t,
    ipfix_t,
    ipv4_t,
    ipv6_addr_t,
    ipv6_t,
    psamp_extended_t,
    tcp_t,
    udp_t,
    vlan_id_t,
    vlan_t,
)
from tests.e2e.sai_p4.instantiations.google.bitwidths import (
    ACL_METADATA_BITWIDTH,
    MIRROR_SESSION_ID_BITWIDTH,
    MULTICAST_GROUP_ID_BITWIDTH,
    NEXTHOP_ID_BITWIDTH,
    PORT_BITWIDTH,
    QOS_QUEUE_BITWIDTH,
    REPLICA_INSTANCE_BITWIDTH,
    ROUTE_METADATA_BITWIDTH,
    ROUTER_INTERFACE_ID_BITWIDTH,
    TUNNEL_ID_BITWIDTH,
    VRF_BITWIDTH,
    WCMP_GROUP_ID_BITWIDTH,
    WCMP_SELECTOR_INPUT_BITWIDTH,
)

# -- Enums --


class PreservedFieldList(p4.enum(p4.bit(8))):
    MIRROR_AND_PACKET_IN_COPY = 1


class MeterColor_t(p4.enum(p4.bit(2))):
    GREEN = 0
    YELLOW = 1
    RED = 2


# -- Translated types (newtypes) --

nexthop_id_t = p4.newtype(p4.bit(NEXTHOP_ID_BITWIDTH), "nexthop_id_t")
tunnel_id_t = p4.newtype(p4.bit(TUNNEL_ID_BITWIDTH), "tunnel_id_t")
wcmp_group_id_t = p4.newtype(p4.bit(WCMP_GROUP_ID_BITWIDTH), "wcmp_group_id_t")
vrf_id_t = p4.newtype(p4.bit(VRF_BITWIDTH), "vrf_id_t")
router_interface_id_t = p4.newtype(
    p4.bit(ROUTER_INTERFACE_ID_BITWIDTH), "router_interface_id_t"
)
port_id_t = p4.newtype(p4.bit(PORT_BITWIDTH), "port_id_t")
mirror_session_id_t = p4.newtype(
    p4.bit(MIRROR_SESSION_ID_BITWIDTH), "mirror_session_id_t"
)
cpu_queue_t = p4.newtype(p4.bit(QOS_QUEUE_BITWIDTH), "cpu_queue_t")
unicast_queue_t = p4.newtype(p4.bit(QOS_QUEUE_BITWIDTH), "unicast_queue_t")
multicast_queue_t = p4.newtype(p4.bit(QOS_QUEUE_BITWIDTH), "multicast_queue_t")

# -- Const --

kDefaultVrf = p4.const(vrf_id_t, 0, "kDefaultVrf")

# -- Untranslated types (typedefs) --

route_metadata_t = p4.typedef(p4.bit(ROUTE_METADATA_BITWIDTH), "route_metadata_t")
acl_metadata_t = p4.typedef(p4.bit(ACL_METADATA_BITWIDTH), "acl_metadata_t")
multicast_group_id_t = p4.typedef(
    p4.bit(MULTICAST_GROUP_ID_BITWIDTH), "multicast_group_id_t"
)
replica_instance_t = p4.typedef(
    p4.bit(REPLICA_INSTANCE_BITWIDTH), "replica_instance_t"
)

# -- Packet IO headers --


class packet_in_header_t(p4.header):
    ingress_port: port_id_t
    target_egress_port: port_id_t
    unused_pad: p4.bit(6)


class packet_out_header_t(p4.header):
    egress_port: port_id_t
    submit_to_ingress: p4.bit(1)
    unused_pad: p4.bit(6)


# -- Structs --


class headers_t(p4.struct):
    packet_in_header: packet_in_header_t
    packet_out_header: packet_out_header_t
    mirror_encap_ethernet: ethernet_t
    mirror_encap_vlan: vlan_t
    mirror_encap_ipv6: ipv6_t
    mirror_encap_udp: udp_t
    mirror_encap_ipfix: ipfix_t
    mirror_encap_psamp_extended: psamp_extended_t
    ethernet: ethernet_t
    vlan: vlan_t
    tunnel_encap_ipv6: ipv6_t
    tunnel_encap_gre: gre_t
    ipv4: ipv4_t
    ipv6: ipv6_t
    hop_by_hop_options: hop_by_hop_options_t
    inner_ipv4: ipv4_t
    inner_ipv6: ipv6_t
    inner_hop_by_hop_options: hop_by_hop_options_t
    icmp: icmp_t
    tcp: tcp_t
    udp: udp_t
    arp: arp_t


class packet_rewrites_t(p4.struct):
    src_mac: ethernet_addr_t
    dst_mac: ethernet_addr_t
    vlan_id: vlan_id_t
    dscp: p4.bit(6)


class local_metadata_t(p4.struct):
    enable_vlan_checks: p4.bool_
    marked_to_drop_by_ingress_vlan_checks: p4.bool_
    omit_vlan_tag_on_egress_packet: p4.bool_
    vlan_id: vlan_id_t
    input_packet_is_vlan_tagged: p4.bool_
    admit_to_l3: p4.bool_
    vrf_id: vrf_id_t
    enable_decrement_ttl: p4.bool_
    enable_src_mac_rewrite: p4.bool_
    enable_dst_mac_rewrite: p4.bool_
    enable_vlan_rewrite: p4.bool_
    enable_dscp_rewrite: p4.bool_
    packet_rewrites: packet_rewrites_t
    l4_src_port: p4.bit(16)
    l4_dst_port: p4.bit(16)
    wcmp_selector_input: p4.bit(WCMP_SELECTOR_INPUT_BITWIDTH)
    apply_tunnel_decap_at_end_of_pre_ingress: p4.bool_
    apply_tunnel_encap_at_egress: p4.bool_
    tunnel_encap_src_ipv6: ipv6_addr_t
    tunnel_encap_dst_ipv6: ipv6_addr_t
    marked_to_copy: p4.bool_
    marked_to_mirror: p4.bool_
    mirror_session_id: mirror_session_id_t
    mirror_egress_port: port_id_t
    mirror_encap_src_mac: ethernet_addr_t
    mirror_encap_dst_mac: ethernet_addr_t
    mirror_encap_vlan_id: vlan_id_t
    mirror_encap_src_ip: ipv6_addr_t
    mirror_encap_dst_ip: ipv6_addr_t
    mirror_encap_udp_src_port: p4.bit(16)
    mirror_encap_udp_dst_port: p4.bit(16)
    packet_in_ingress_port: p4.bit(PORT_BITWIDTH)
    packet_in_target_egress_port: p4.bit(PORT_BITWIDTH)
    redirect_port_valid: p4.bool_
    redirect_port: p4.bit(PORT_BITWIDTH)
    color: MeterColor_t
    ingress_port: port_id_t
    route_metadata: route_metadata_t
    acl_metadata: acl_metadata_t
    bypass_ingress: p4.bool_
    bypass_egress: p4.bool_
    wcmp_group_id_valid: p4.bool_
    wcmp_group_id_value: wcmp_group_id_t
    nexthop_id_valid: p4.bool_
    nexthop_id_value: nexthop_id_t
    route_hit: p4.bool_
    tunnel_termination_table_hit: p4.bool_
    acl_ingress_ipmc_redirect: p4.bool_
    acl_ingress_l2mc_redirect: p4.bool_
    acl_ingress_nexthop_redirect: p4.bool_
    acl_drop: p4.bool_
