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
from tests.e2e.sai_p4.fixed.metadata import (
    headers_t,
    local_metadata_t,
    multicast_group_id_t,
    nexthop_id_t,
    route_metadata_t,
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
            if (headers.ethernet.dst_addr[47:24] == 0x01005E) and (
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
            if headers.ethernet.dst_addr[47:32] == 0x3333:
                if not local_metadata.marked_to_drop_by_ingress_vlan_checks:
                    local_metadata.route_hit = ipv6_multicast_table.apply().hit
        else:
            # IS_UNICAST_MAC(headers.ethernet.dst_addr)
            if (
                headers.ethernet.dst_addr[40:40] == 0
            ) and local_metadata.admit_to_l3:
                local_metadata.route_hit = ipv6_table.apply().hit
