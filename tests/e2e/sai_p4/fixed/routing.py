"""P4Py translation of sai_p4/fixed/routing.p4 (TOR instantiation).

Contains the file-scope set_nexthop_id action and two control blocks:
routing_lookup and routing_resolution.

Conditional compilation (#if defined) is resolved for the TOR instantiation.
Macros (IS_MULTICAST_IPV4 etc.) are inlined as expressions.
Annotations (@id, @refers_to, etc.) are omitted.
"""

import p4py.lang as p4
from p4py.arch import v1model
from p4py.arch.v1model import standard_metadata_t
from tests.e2e.sai_p4.fixed.headers import (
    INTERNAL_VLAN_ID,
    ethernet_addr_t,
    ipv6_addr_t,
    vlan_id_t,
)
from tests.e2e.sai_p4.fixed.metadata import (
    headers_t,
    local_metadata_t,
    multicast_group_id_t,
    nexthop_id_t,
    port_id_t,
    route_metadata_t,
    router_interface_id_t,
    tunnel_id_t,
    wcmp_group_id_t,
)

# --- File-scope action (shared between routing_lookup and routing_resolution) ---


@p4.action
def set_nexthop_id(
    local_metadata: p4.inout(local_metadata_t), nexthop_id: nexthop_id_t
):
    local_metadata.nexthop_id_valid = True
    local_metadata.nexthop_id_value = nexthop_id


# --- routing_lookup control ---


@p4.control
def routing_lookup(
    headers: p4.in_(headers_t),
    local_metadata: p4.inout(local_metadata_t),
    standard_metadata: p4.inout(standard_metadata_t),
):
    @p4.action
    def no_action():
        pass

    vrf_table = p4.table(
        key={local_metadata.vrf_id: p4.exact},
        actions=[no_action],
        default_action=no_action,
    )

    @p4.action
    def drop():
        v1model.mark_to_drop(standard_metadata)

    @p4.action
    def set_wcmp_group_id(wcmp_group_id: wcmp_group_id_t):
        local_metadata.wcmp_group_id_valid = True
        local_metadata.wcmp_group_id_value = wcmp_group_id

    @p4.action
    def set_wcmp_group_id_and_metadata(
        wcmp_group_id: wcmp_group_id_t, route_metadata: route_metadata_t
    ):
        set_wcmp_group_id(wcmp_group_id)
        local_metadata.route_metadata = route_metadata

    @p4.action
    def set_metadata_and_drop(route_metadata: route_metadata_t):
        local_metadata.route_metadata = route_metadata
        v1model.mark_to_drop(standard_metadata)

    @p4.action
    def set_nexthop_id_and_metadata(
        nexthop_id: nexthop_id_t, route_metadata: route_metadata_t
    ):
        local_metadata.nexthop_id_valid = True
        local_metadata.nexthop_id_value = nexthop_id
        local_metadata.route_metadata = route_metadata

    @p4.action
    def set_multicast_group_id(multicast_group_id: multicast_group_id_t):
        standard_metadata.mcast_grp = multicast_group_id

    ipv4_table = p4.table(
        key={
            local_metadata.vrf_id: p4.exact,
            headers.ipv4.dst_addr: p4.lpm,
        },
        actions=[
            drop,
            set_nexthop_id(local_metadata),
            set_wcmp_group_id,
            set_nexthop_id_and_metadata,
            set_wcmp_group_id_and_metadata,
            set_metadata_and_drop,
        ],
        default_action=drop,
    )

    ipv6_table = p4.table(
        key={
            local_metadata.vrf_id: p4.exact,
            headers.ipv6.dst_addr: p4.lpm,
        },
        actions=[
            drop,
            set_nexthop_id(local_metadata),
            set_wcmp_group_id,
            set_nexthop_id_and_metadata,
            set_wcmp_group_id_and_metadata,
            set_metadata_and_drop,
        ],
        default_action=drop,
    )

    ipv4_multicast_table = p4.table(
        key={
            local_metadata.vrf_id: p4.exact,
            headers.ipv4.dst_addr: p4.exact,
        },
        actions=[set_multicast_group_id],
    )

    ipv6_multicast_table = p4.table(
        key={
            local_metadata.vrf_id: p4.exact,
            headers.ipv6.dst_addr: p4.exact,
        },
        actions=[set_multicast_group_id],
    )

    v1model.mark_to_drop(standard_metadata)
    vrf_table.apply()

    if headers.ipv4.isValid():
        # IS_MULTICAST_IPV4(headers.ipv4.dst_addr)
        if (headers.ipv4.dst_addr & 0xF0000000) == 0xE0000000:
            # IS_IPV4_MULTICAST_MAC(headers.ethernet.dst_addr)
            if (headers.ethernet.dst_addr[47:24] == 0x01005E) and (  # noqa: SIM102
                headers.ethernet.dst_addr[23:23] == 0
            ):
                if not local_metadata.marked_to_drop_by_ingress_vlan_checks:
                    local_metadata.route_hit = ipv4_multicast_table.apply().hit
        else:
            # IS_UNICAST_MAC(headers.ethernet.dst_addr)
            if (
                headers.ethernet.dst_addr[40:40] == 0
            ) and local_metadata.admit_to_l3:
                local_metadata.route_hit = ipv4_table.apply().hit
    elif headers.ipv6.isValid():
        # IS_MULTICAST_IPV6(headers.ipv6.dst_addr)
        if (
            headers.ipv6.dst_addr & 0xFF000000000000000000000000000000
        ) == 0xFF000000000000000000000000000000:
            # IS_IPV6_MULTICAST_MAC(headers.ethernet.dst_addr)
            if headers.ethernet.dst_addr[47:32] == 0x3333:  # noqa: SIM102
                if not local_metadata.marked_to_drop_by_ingress_vlan_checks:
                    local_metadata.route_hit = ipv6_multicast_table.apply().hit
        else:
            # IS_UNICAST_MAC(headers.ethernet.dst_addr)
            if (
                headers.ethernet.dst_addr[40:40] == 0
            ) and local_metadata.admit_to_l3:
                local_metadata.route_hit = ipv6_table.apply().hit


# --- routing_resolution control ---

@p4.control
def routing_resolution(
    headers: p4.in_(headers_t),
    local_metadata: p4.inout(local_metadata_t),
    standard_metadata: p4.inout(standard_metadata_t),
):
    # Control-local variables.
    tunnel_id_valid = p4.bool_(False)
    tunnel_id_value = p4.var(tunnel_id_t)

    router_interface_id_valid = p4.bool_(False)
    router_interface_id_value = p4.var(router_interface_id_t)

    neighbor_id_valid = p4.bool_(False)
    neighbor_id_value = p4.var(ipv6_addr_t)

    # --- Actions ---

    @p4.action
    def set_dst_mac(dst_mac: ethernet_addr_t):
        local_metadata.packet_rewrites.dst_mac = dst_mac

    @p4.action
    def unicast_set_port_and_src_mac_and_vlan_id(
        port: port_id_t, src_mac: ethernet_addr_t, vlan_id: vlan_id_t
    ):
        standard_metadata.egress_spec = p4.cast(p4.bit(9), port)
        local_metadata.packet_rewrites.src_mac = src_mac
        local_metadata.packet_rewrites.vlan_id = vlan_id

    @p4.action
    def set_port_and_src_mac(port: port_id_t, src_mac: ethernet_addr_t):
        unicast_set_port_and_src_mac_and_vlan_id(port, src_mac, INTERNAL_VLAN_ID)

    @p4.action
    def unicast_set_port_and_src_mac(port: port_id_t, src_mac: ethernet_addr_t):
        unicast_set_port_and_src_mac_and_vlan_id(port, src_mac, INTERNAL_VLAN_ID)

    @p4.action
    def set_ip_nexthop_and_disable_rewrites(
        router_interface_id: router_interface_id_t,
        neighbor_id: ipv6_addr_t,
        disable_decrement_ttl: p4.bit(1),
        disable_src_mac_rewrite: p4.bit(1),
        disable_dst_mac_rewrite: p4.bit(1),
        disable_vlan_rewrite: p4.bit(1),
    ):
        router_interface_id_valid = True  # noqa: F841
        router_interface_id_value = router_interface_id  # noqa: F841
        neighbor_id_valid = True  # noqa: F841
        neighbor_id_value = neighbor_id  # noqa: F841
        local_metadata.enable_decrement_ttl = not p4.cast(p4.bool, disable_decrement_ttl)
        local_metadata.enable_src_mac_rewrite = not p4.cast(p4.bool, disable_src_mac_rewrite)
        local_metadata.enable_dst_mac_rewrite = not p4.cast(p4.bool, disable_dst_mac_rewrite)
        local_metadata.enable_vlan_rewrite = not p4.cast(p4.bool, disable_vlan_rewrite)

    @p4.action
    def set_ip_nexthop(
        router_interface_id: router_interface_id_t,
        neighbor_id: ipv6_addr_t,
    ):
        set_ip_nexthop_and_disable_rewrites(
            router_interface_id, neighbor_id, 0x0, 0x0, 0x0, 0x0
        )

    @p4.action
    def set_p2p_tunnel_encap_nexthop(tunnel_id: tunnel_id_t):
        tunnel_id_valid = True  # noqa: F841
        tunnel_id_value = tunnel_id  # noqa: F841

    @p4.action
    def mark_for_p2p_tunnel_encap(
        encap_src_ip: ipv6_addr_t,
        encap_dst_ip: ipv6_addr_t,
        router_interface_id: router_interface_id_t,
    ):
        local_metadata.tunnel_encap_src_ipv6 = encap_src_ip
        local_metadata.tunnel_encap_dst_ipv6 = encap_dst_ip
        local_metadata.apply_tunnel_encap_at_egress = True
        set_ip_nexthop(router_interface_id, encap_dst_ip)

    # --- Tables ---

    neighbor_table = p4.table(
        key={
            router_interface_id_value: p4.exact,
            neighbor_id_value: p4.exact,
        },
        actions=[set_dst_mac, p4.NoAction],
        default_action=p4.NoAction,
    )

    router_interface_table = p4.table(
        key={router_interface_id_value: p4.exact},
        actions=[
            set_port_and_src_mac,
            unicast_set_port_and_src_mac_and_vlan_id,
            unicast_set_port_and_src_mac,
            p4.NoAction,
        ],
        default_action=p4.NoAction,
    )

    nexthop_table = p4.table(
        key={local_metadata.nexthop_id_value: p4.exact},
        actions=[
            set_ip_nexthop,
            set_p2p_tunnel_encap_nexthop,
            set_ip_nexthop_and_disable_rewrites,
            p4.NoAction,
        ],
        default_action=p4.NoAction,
    )

    tunnel_table = p4.table(
        key={tunnel_id_value: p4.exact},
        actions=[mark_for_p2p_tunnel_encap, p4.NoAction],
        default_action=p4.NoAction,
    )

    wcmp_group_selector = p4.action_selector(
        v1model.HashAlgorithm.identity, 31296, 16
    )

    wcmp_group_table = p4.table(
        key={
            local_metadata.wcmp_group_id_value: p4.exact,
            local_metadata.wcmp_selector_input: p4.selector,
        },
        actions=[set_nexthop_id(local_metadata), p4.NoAction],
        default_action=p4.NoAction,
        implementation=wcmp_group_selector,
    )

    # --- Apply block ---

    if local_metadata.wcmp_group_id_valid:
        wcmp_group_table.apply()

    if local_metadata.nexthop_id_valid:
        nexthop_table.apply()
        if tunnel_id_valid:
            tunnel_table.apply()
        if router_interface_id_valid and neighbor_id_valid:
            router_interface_table.apply()
            neighbor_table.apply()

    if local_metadata.redirect_port_valid:
        standard_metadata.egress_spec = local_metadata.redirect_port

    local_metadata.packet_in_target_egress_port = standard_metadata.egress_spec
    local_metadata.packet_in_ingress_port = standard_metadata.ingress_port

    if local_metadata.acl_drop:
        v1model.mark_to_drop(standard_metadata)
