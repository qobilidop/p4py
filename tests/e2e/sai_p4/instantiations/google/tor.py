"""P4Py translation of sai_p4/instantiations/google/tor.p4 (PLATFORM_BMV2)."""

import p4py.lang as p4
from p4py.arch import v1model
from p4py.arch.v1model import V1Switch
from tests.e2e.sai_p4.fixed import ids as _c
from tests.e2e.sai_p4.fixed.headers import (
    INTERNAL_VLAN_ID,
    NO_VLAN_ID,
    ether_type_t,
    ethernet_addr_t,
    ipv4_addr_t,
    ipv6_addr_t,
    vlan_id_t,
)
from tests.e2e.sai_p4.fixed.l3_admit import admit_google_system_mac, l3_admit
from tests.e2e.sai_p4.fixed.metadata import (
    MeterColor_t,
    PreservedFieldList,
    acl_metadata_t,
    cpu_queue_t,
    headers_t,
    kDefaultVrf,
    local_metadata_t,
    mirror_session_id_t,
    multicast_group_id_t,
    multicast_queue_t,
    nexthop_id_t,
    port_id_t,
    replica_instance_t,
    route_metadata_t,
    router_interface_id_t,
    tunnel_id_t,
    unicast_queue_t,
    vrf_id_t,
    wcmp_group_id_t,
)
from tests.e2e.sai_p4.fixed.packet_io import packet_out_decap
from tests.e2e.sai_p4.fixed.routing import (
    routing_lookup,
    routing_resolution,
    set_nexthop_id,
)
from tests.e2e.sai_p4.fixed.vlan import (
    egress_vlan_checks,
    ingress_vlan_checks,
    vlan_tag,
    vlan_untag,
)
from tests.e2e.sai_p4.instantiations.google.acl_ingress import acl_ingress
from tests.e2e.sai_p4.instantiations.google.acl_pre_ingress import acl_pre_ingress


@p4.parser
def packet_parser(
    packet, headers: headers_t, local_metadata: local_metadata_t, standard_metadata
):
    def start():
        # Initialize metadata fields.
        local_metadata.enable_vlan_checks = False
        local_metadata.marked_to_drop_by_ingress_vlan_checks = False
        local_metadata.vlan_id = 0
        local_metadata.input_packet_is_vlan_tagged = False
        local_metadata.omit_vlan_tag_on_egress_packet = False
        local_metadata.admit_to_l3 = False
        local_metadata.vrf_id = kDefaultVrf
        local_metadata.enable_decrement_ttl = False
        local_metadata.enable_src_mac_rewrite = False
        local_metadata.enable_dst_mac_rewrite = False
        local_metadata.enable_vlan_rewrite = False
        local_metadata.enable_dscp_rewrite = False
        local_metadata.packet_rewrites.src_mac = 0
        local_metadata.packet_rewrites.dst_mac = 0
        local_metadata.packet_rewrites.dscp = 0
        local_metadata.l4_src_port = 0
        local_metadata.l4_dst_port = 0
        local_metadata.wcmp_selector_input = 0
        local_metadata.apply_tunnel_decap_at_end_of_pre_ingress = False
        local_metadata.apply_tunnel_encap_at_egress = False
        local_metadata.tunnel_encap_src_ipv6 = 0
        local_metadata.tunnel_encap_dst_ipv6 = 0
        local_metadata.marked_to_copy = False
        local_metadata.marked_to_mirror = False
        local_metadata.mirror_session_id = 0
        local_metadata.mirror_egress_port = 0
        local_metadata.color = MeterColor_t.GREEN
        local_metadata.ingress_port = p4.cast(port_id_t, standard_metadata.ingress_port)
        local_metadata.route_metadata = 0
        local_metadata.bypass_ingress = False
        local_metadata.bypass_egress = False
        local_metadata.wcmp_group_id_valid = False
        local_metadata.wcmp_group_id_value = 0
        local_metadata.nexthop_id_valid = False
        local_metadata.acl_ingress_l2mc_redirect = False
        local_metadata.nexthop_id_value = 0
        local_metadata.route_hit = False
        local_metadata.acl_drop = False
        local_metadata.tunnel_termination_table_hit = False
        local_metadata.acl_ingress_ipmc_redirect = False
        local_metadata.redirect_port_valid = False
        local_metadata.redirect_port = 0
        local_metadata.acl_ingress_nexthop_redirect = False
        match standard_metadata.ingress_port:
            case _c.SAI_P4_CPU_PORT:
                return parse_packet_out_header
            case _:
                return parse_ethernet

    def parse_packet_out_header():
        packet.extract(headers.packet_out_header)
        return parse_ethernet

    def parse_ethernet():
        packet.extract(headers.ethernet)
        match headers.ethernet.ether_type:
            case _c.ETHERTYPE_IPV4:
                return parse_ipv4
            case _c.ETHERTYPE_IPV6:
                return parse_ipv6
            case _c.ETHERTYPE_ARP:
                return parse_arp
            case _:
                return p4.ACCEPT

    def parse_ipv4():
        packet.extract(headers.ipv4)
        match headers.ipv4.protocol:
            case _c.IP_PROTOCOL_IPV4:
                return parse_ipv4_in_ip
            case _c.IP_PROTOCOL_IPV6:
                return parse_ipv6_in_ip
            case _c.IP_PROTOCOL_ICMP:
                return parse_icmp
            case _c.IP_PROTOCOL_TCP:
                return parse_tcp
            case _c.IP_PROTOCOL_UDP:
                return parse_udp
            case _:
                return p4.ACCEPT

    def parse_ipv4_in_ip():
        packet.extract(headers.inner_ipv4)
        match headers.inner_ipv4.protocol:
            case _c.IP_PROTOCOL_ICMP:
                return parse_icmp
            case _c.IP_PROTOCOL_TCP:
                return parse_tcp
            case _c.IP_PROTOCOL_UDP:
                return parse_udp
            case _:
                return p4.ACCEPT

    def parse_ipv6():
        packet.extract(headers.ipv6)
        match headers.ipv6.next_header:
            case _c.IP_PROTOCOL_V6_EXTENSION_HOP_BY_HOP:
                return parse_hop_by_hop_options
            case _c.IP_PROTOCOL_IPV4:
                return parse_ipv4_in_ip
            case _c.IP_PROTOCOL_IPV6:
                return parse_ipv6_in_ip
            case _c.IP_PROTOCOL_ICMPV6:
                return parse_icmp
            case _c.IP_PROTOCOL_TCP:
                return parse_tcp
            case _c.IP_PROTOCOL_UDP:
                return parse_udp
            case _:
                return p4.ACCEPT

    def parse_hop_by_hop_options():
        packet.extract(headers.hop_by_hop_options)
        match headers.hop_by_hop_options.header_extension_length:
            case 0:
                return next_header_for_hop_by_hop_options
            case _:
                return p4.ACCEPT

    def next_header_for_hop_by_hop_options():
        match headers.hop_by_hop_options.next_header:
            case _c.IP_PROTOCOL_IPV4:
                return parse_ipv4_in_ip
            case _c.IP_PROTOCOL_IPV6:
                return parse_ipv6_in_ip
            case _c.IP_PROTOCOL_ICMPV6:
                return parse_icmp
            case _c.IP_PROTOCOL_TCP:
                return parse_tcp
            case _c.IP_PROTOCOL_UDP:
                return parse_udp
            case _:
                return p4.ACCEPT

    def parse_ipv6_in_ip():
        packet.extract(headers.inner_ipv6)
        match headers.inner_ipv6.next_header:
            case _c.IP_PROTOCOL_V6_EXTENSION_HOP_BY_HOP:
                return parse_hop_by_hop_options_in_ip
            case _c.IP_PROTOCOL_ICMPV6:
                return parse_icmp
            case _c.IP_PROTOCOL_TCP:
                return parse_tcp
            case _c.IP_PROTOCOL_UDP:
                return parse_udp
            case _:
                return p4.ACCEPT

    def parse_hop_by_hop_options_in_ip():
        packet.extract(headers.inner_hop_by_hop_options)
        match headers.inner_hop_by_hop_options.header_extension_length:
            case 0:
                return next_header_for_hop_by_hop_options_in_ip
            case _:
                return p4.ACCEPT

    def next_header_for_hop_by_hop_options_in_ip():
        match headers.inner_hop_by_hop_options.next_header:
            case _c.IP_PROTOCOL_ICMPV6:
                return parse_icmp
            case _c.IP_PROTOCOL_TCP:
                return parse_tcp
            case _c.IP_PROTOCOL_UDP:
                return parse_udp
            case _:
                return p4.ACCEPT

    def parse_tcp():
        packet.extract(headers.tcp)
        local_metadata.l4_src_port = headers.tcp.src_port
        local_metadata.l4_dst_port = headers.tcp.dst_port
        return p4.ACCEPT

    def parse_udp():
        packet.extract(headers.udp)
        local_metadata.l4_src_port = headers.udp.src_port
        local_metadata.l4_dst_port = headers.udp.dst_port
        return p4.ACCEPT

    def parse_icmp():
        packet.extract(headers.icmp)
        return p4.ACCEPT

    def parse_arp():
        packet.extract(headers.arp)
        return p4.ACCEPT


@p4.control
def ingress(headers, local_metadata, standard_metadata):
    packet_out_decap.apply(headers, local_metadata, standard_metadata)
    if not local_metadata.bypass_ingress:
        vlan_untag.apply(headers, local_metadata, standard_metadata)
        acl_pre_ingress.apply(headers, local_metadata, standard_metadata)
        ingress_vlan_checks.apply(headers, local_metadata, standard_metadata)
        admit_google_system_mac.apply(headers, local_metadata)
        l3_admit.apply(headers, local_metadata, standard_metadata)
        routing_lookup.apply(headers, local_metadata, standard_metadata)
        acl_ingress.apply(headers, local_metadata, standard_metadata)
        routing_resolution.apply(headers, local_metadata, standard_metadata)


@p4.control
def egress(headers, local_metadata, standard_metadata):
    if not local_metadata.bypass_egress:
        egress_vlan_checks.apply(headers, local_metadata, standard_metadata)
        vlan_tag.apply(headers, local_metadata, standard_metadata)


@p4.control
def verify_ipv4_checksum(headers, local_metadata):
    v1model.verify_checksum(
        condition=headers.ipv4.isValid(),
        data=[
            headers.ipv4.version,
            headers.ipv4.ihl,
            headers.ipv4.dscp,
            headers.ipv4.ecn,
            headers.ipv4.total_len,
            headers.ipv4.identification,
            headers.ipv4.reserved,
            headers.ipv4.do_not_fragment,
            headers.ipv4.more_fragments,
            headers.ipv4.frag_offset,
            headers.ipv4.ttl,
            headers.ipv4.protocol,
            headers.ipv4.src_addr,
            headers.ipv4.dst_addr,
        ],
        checksum=headers.ipv4.header_checksum,
        algo=v1model.HashAlgorithm.csum16,
    )


@p4.control
def compute_ipv4_checksum(headers, local_metadata):
    v1model.update_checksum(
        condition=headers.ipv4.isValid(),
        data=[
            headers.ipv4.version,
            headers.ipv4.ihl,
            headers.ipv4.dscp,
            headers.ipv4.ecn,
            headers.ipv4.total_len,
            headers.ipv4.identification,
            headers.ipv4.reserved,
            headers.ipv4.do_not_fragment,
            headers.ipv4.more_fragments,
            headers.ipv4.frag_offset,
            headers.ipv4.ttl,
            headers.ipv4.protocol,
            headers.ipv4.src_addr,
            headers.ipv4.dst_addr,
        ],
        checksum=headers.ipv4.header_checksum,
        algo=v1model.HashAlgorithm.csum16,
    )


@p4.deparser
def packet_deparser(packet, headers):
    packet.emit(headers.packet_out_header)
    packet.emit(headers.packet_in_header)
    packet.emit(headers.mirror_encap_ethernet)
    packet.emit(headers.mirror_encap_vlan)
    packet.emit(headers.mirror_encap_ipv6)
    packet.emit(headers.mirror_encap_udp)
    packet.emit(headers.mirror_encap_ipfix)
    packet.emit(headers.mirror_encap_psamp_extended)
    packet.emit(headers.ethernet)
    packet.emit(headers.tunnel_encap_ipv6)
    packet.emit(headers.tunnel_encap_gre)
    packet.emit(headers.ipv4)
    packet.emit(headers.ipv6)
    packet.emit(headers.hop_by_hop_options)
    packet.emit(headers.inner_ipv4)
    packet.emit(headers.inner_ipv6)
    packet.emit(headers.inner_hop_by_hop_options)
    packet.emit(headers.arp)
    packet.emit(headers.icmp)
    packet.emit(headers.tcp)
    packet.emit(headers.udp)


main = V1Switch(
    parser=packet_parser,
    verify_checksum=verify_ipv4_checksum,
    ingress=ingress,
    egress=egress,
    compute_checksum=compute_ipv4_checksum,
    deparser=packet_deparser,
    sub_controls=(
        packet_out_decap,
        vlan_untag,
        acl_pre_ingress,
        ingress_vlan_checks,
        admit_google_system_mac,
        l3_admit,
        routing_lookup,
        acl_ingress,
        routing_resolution,
        egress_vlan_checks,
        vlan_tag,
    ),
    file_scope_actions=(set_nexthop_id,),
    declarations=(
        # Typedefs from headers.
        ethernet_addr_t,
        ipv4_addr_t,
        ipv6_addr_t,
        vlan_id_t,
        ether_type_t,
        # Enums.
        PreservedFieldList,
        MeterColor_t,
        # Newtypes (translated types).
        nexthop_id_t,
        tunnel_id_t,
        wcmp_group_id_t,
        vrf_id_t,
        router_interface_id_t,
        port_id_t,
        mirror_session_id_t,
        cpu_queue_t,
        unicast_queue_t,
        multicast_queue_t,
        # Typedefs (untranslated types).
        route_metadata_t,
        acl_metadata_t,
        multicast_group_id_t,
        replica_instance_t,
        # Consts.
        INTERNAL_VLAN_ID,
        NO_VLAN_ID,
        kDefaultVrf,
        # ids.py typedefs.
        _c._ip_protocol_t,
        _c._instance_type_t,
        # ids.py consts.
        _c.SAI_P4_CPU_PORT,
        _c.ETHERTYPE_IPV4,
        _c.ETHERTYPE_IPV6,
        _c.ETHERTYPE_ARP,
        _c.ETHERTYPE_8021Q,
        _c.IP_PROTOCOL_ICMP,
        _c.IP_PROTOCOL_IPV4,
        _c.IP_PROTOCOL_TCP,
        _c.IP_PROTOCOL_UDP,
        _c.IP_PROTOCOL_IPV6,
        _c.IP_PROTOCOL_ICMPV6,
        _c.IP_PROTOCOL_V6_EXTENSION_HOP_BY_HOP,
        _c.PKT_INSTANCE_TYPE_INGRESS_CLONE,
        _c.PKT_INSTANCE_TYPE_EGRESS_CLONE,
        _c.PKT_INSTANCE_TYPE_REPLICATION,
    ),
)
