"""P4Py translation of sai_p4/instantiations/google/acl_ingress.p4 (TOR)."""

import p4py.lang as p4
from p4py.arch import v1model
from p4py.arch.v1model import standard_metadata_t
from tests.e2e.sai_p4.fixed.metadata import (
    MeterColor_t,
    cpu_queue_t,
    headers_t,
    local_metadata_t,
    mirror_session_id_t,
    multicast_group_id_t,
    multicast_queue_t,
    nexthop_id_t,
    port_id_t,
    unicast_queue_t,
)


@p4.control
def acl_ingress(
    headers: p4.in_(headers_t),
    local_metadata: p4.inout(local_metadata_t),
    standard_metadata: p4.inout(standard_metadata_t),
):
    # IPv4 TTL or IPv6 hoplimit bits (or 0, for non-IP packets)
    ttl = p4.bit(8)
    # First 6 bits of IPv4 TOS or IPv6 traffic class (or 0, for non-IP packets)
    dscp = p4.bit(6)
    # Last 2 bits of IPv4 TOS or IPv6 traffic class (or 0, for non-IP packets)
    ecn = p4.bit(2)
    # IPv4 IP protocol or IPv6 next_header (or 0, for non-IP packets)
    ip_protocol = p4.bit(8)
    # Cancels out local_metadata.marked_to_copy when true.
    cancel_copy = p4.bool_(False)

    acl_ingress_meter = v1model.direct_meter(MeterColor_t, "bytes")  # noqa: F841
    acl_ingress_qos_meter = v1model.direct_meter(MeterColor_t, "bytes")
    acl_ingress_counter = v1model.direct_counter("packets_and_bytes")
    acl_ingress_qos_counter = v1model.direct_counter("packets_and_bytes")
    acl_ingress_counting_counter = v1model.direct_counter("packets_and_bytes")
    acl_ingress_security_counter = v1model.direct_counter("packets_and_bytes")  # noqa: F841

    # -- Actions --

    # TOR variant: no meter read in copy action
    @p4.action
    def acl_copy(qos_queue: cpu_queue_t):
        acl_ingress_counter.count()
        local_metadata.marked_to_copy = True

    @p4.action
    def acl_trap(qos_queue: cpu_queue_t):
        acl_copy(qos_queue)
        local_metadata.acl_drop = True

    # TOR variant: no meter read in forward action
    @p4.action
    def acl_forward():
        pass

    @p4.action
    def acl_count():
        acl_ingress_counting_counter.count()

    @p4.action
    def acl_mirror(mirror_session_id: mirror_session_id_t):
        acl_ingress_counter.count()
        local_metadata.marked_to_mirror = True
        local_metadata.mirror_session_id = mirror_session_id

    @p4.action
    def set_qos_queue_and_cancel_copy_above_rate_limit(qos_queue: cpu_queue_t):
        acl_ingress_qos_meter.read(local_metadata.color)

    @p4.action
    def set_cpu_queue_and_cancel_copy(cpu_queue: cpu_queue_t):
        cancel_copy = True  # noqa: F841

    @p4.action
    def set_dscp_and_queues_and_deny_above_rate_limit(
        dscp: p4.bit(6),
        cpu_queue: cpu_queue_t,
        green_multicast_queue: multicast_queue_t,
        red_multicast_queue: multicast_queue_t,
        green_unicast_queue: unicast_queue_t,
        red_unicast_queue: unicast_queue_t,
    ):
        acl_ingress_qos_meter.read(local_metadata.color)
        local_metadata.enable_dscp_rewrite = True
        local_metadata.packet_rewrites.dscp = dscp

    @p4.action
    def set_cpu_queue_and_deny_above_rate_limit(cpu_queue: cpu_queue_t):
        acl_ingress_qos_meter.read(local_metadata.color)

    @p4.action
    def set_cpu_queue(cpu_queue: cpu_queue_t):
        pass

    @p4.action
    def set_forwarding_queues(
        green_multicast_queue: multicast_queue_t,
        red_multicast_queue: multicast_queue_t,
        green_unicast_queue: unicast_queue_t,
        red_unicast_queue: unicast_queue_t,
    ):
        acl_ingress_qos_meter.read(local_metadata.color)

    @p4.action
    def acl_deny():
        cancel_copy = True  # noqa: F841
        local_metadata.acl_drop = True

    @p4.action
    def acl_drop():
        local_metadata.acl_drop = True

    @p4.action
    def redirect_to_nexthop(nexthop_id: nexthop_id_t):
        local_metadata.acl_ingress_nexthop_redirect = True
        local_metadata.nexthop_id_valid = True
        local_metadata.nexthop_id_value = nexthop_id
        local_metadata.wcmp_group_id_valid = False
        standard_metadata.mcast_grp = 0

    @p4.action
    def redirect_to_ipmc_group(multicast_group_id: multicast_group_id_t):
        standard_metadata.mcast_grp = multicast_group_id
        local_metadata.acl_ingress_ipmc_redirect = True
        local_metadata.nexthop_id_valid = False
        local_metadata.wcmp_group_id_valid = False

    @p4.action
    def redirect_to_port(redirect_port: port_id_t):
        local_metadata.redirect_port = p4.cast(p4.bit(9), redirect_port)
        local_metadata.redirect_port_valid = True
        local_metadata.wcmp_group_id_valid = False
        standard_metadata.mcast_grp = 0

    @p4.action
    def acl_mirror_and_redirect_to_port(
        mirror_session_id: mirror_session_id_t, redirect_port: port_id_t
    ):
        acl_ingress_counter.count()
        local_metadata.marked_to_mirror = True
        local_metadata.mirror_session_id = mirror_session_id
        local_metadata.redirect_port = p4.cast(p4.bit(9), redirect_port)
        local_metadata.redirect_port_valid = True
        local_metadata.wcmp_group_id_valid = False
        standard_metadata.mcast_grp = 0

    @p4.action
    def redirect_to_l2mc_group(multicast_group_id: multicast_group_id_t):
        local_metadata.acl_ingress_l2mc_redirect = True
        standard_metadata.mcast_grp = multicast_group_id
        local_metadata.nexthop_id_valid = False
        local_metadata.wcmp_group_id_valid = False

    # -- Tables --

    # TOR acl_ingress_table: no dscp/ecn keys, has icmp_type, arp_tpa,
    # in_port, route_metadata, acl_metadata, vlan_id
    acl_ingress_table = p4.table(
        key={
            headers.ipv4.isValid() or headers.ipv6.isValid(): p4.optional,
            headers.ipv4.isValid(): p4.optional,
            headers.ipv6.isValid(): p4.optional,
            headers.ethernet.ether_type: p4.ternary,
            headers.ethernet.dst_addr: p4.ternary,
            headers.ipv4.src_addr: p4.ternary,
            headers.ipv4.dst_addr: p4.ternary,
            headers.ipv6.src_addr[127:64]: p4.ternary,
            headers.ipv6.dst_addr[127:64]: p4.ternary,
            ttl: p4.ternary,
            ip_protocol: p4.ternary,
            headers.icmp.type: p4.ternary,
            local_metadata.l4_src_port: p4.ternary,
            local_metadata.l4_dst_port: p4.ternary,
            headers.arp.target_proto_addr: p4.ternary,
            local_metadata.ingress_port: p4.optional,
            local_metadata.route_metadata: p4.optional,
            local_metadata.acl_metadata: p4.ternary,
            local_metadata.vlan_id: p4.ternary,
        },
        actions=[
            acl_copy,
            acl_trap,
            acl_forward,
            acl_mirror,
            acl_drop,
            redirect_to_l2mc_group,
            redirect_to_nexthop,
            p4.NoAction,
        ],
        default_action=p4.NoAction,
        counters=acl_ingress_counter,
    )

    # TOR acl_ingress_qos_table: includes dst_mac, arp_tpa, in_port, vlan_id
    acl_ingress_qos_table = p4.table(
        key={
            headers.ipv4.isValid() or headers.ipv6.isValid(): p4.optional,
            headers.ipv4.isValid(): p4.optional,
            headers.ipv6.isValid(): p4.optional,
            headers.ethernet.ether_type: p4.ternary,
            ttl: p4.ternary,
            ip_protocol: p4.ternary,
            headers.icmp.type: p4.ternary,
            local_metadata.l4_dst_port: p4.ternary,
            local_metadata.acl_metadata: p4.ternary,
            local_metadata.route_metadata: p4.ternary,
            headers.ethernet.dst_addr: p4.ternary,
            headers.arp.target_proto_addr: p4.ternary,
            local_metadata.ingress_port: p4.optional,
            local_metadata.vlan_id: p4.ternary,
        },
        actions=[
            set_qos_queue_and_cancel_copy_above_rate_limit,
            set_cpu_queue_and_deny_above_rate_limit,
            acl_forward,
            acl_drop,
            set_cpu_queue,
            set_dscp_and_queues_and_deny_above_rate_limit,
            set_forwarding_queues,
            p4.NoAction,
        ],
        default_action=p4.NoAction,
        meters=acl_ingress_qos_meter,
        counters=acl_ingress_qos_counter,
    )

    # acl_ingress_mirror_and_redirect_table
    acl_ingress_mirror_and_redirect_table = p4.table(
        key={
            local_metadata.ingress_port: p4.optional,
            local_metadata.acl_metadata: p4.ternary,
            local_metadata.vlan_id: p4.ternary,
            headers.ipv4.isValid() or headers.ipv6.isValid(): p4.optional,
            headers.ipv4.isValid(): p4.optional,
            headers.ipv6.isValid(): p4.optional,
            headers.ipv4.dst_addr: p4.ternary,
            headers.ipv6.dst_addr[127:64]: p4.ternary,
            local_metadata.vrf_id: p4.optional,
        },
        actions=[
            acl_mirror,
            acl_mirror_and_redirect_to_port,
            redirect_to_port,
            acl_forward,
            redirect_to_nexthop,
            redirect_to_ipmc_group,
            set_cpu_queue_and_cancel_copy,
            p4.NoAction,
        ],
        default_action=p4.NoAction,
    )

    # Apply block
    if headers.ipv4.isValid():
        ttl = headers.ipv4.ttl
        dscp = headers.ipv4.dscp
        ecn = headers.ipv4.ecn
        ip_protocol = headers.ipv4.protocol
    elif headers.ipv6.isValid():
        ttl = headers.ipv6.hop_limit
        dscp = headers.ipv6.dscp  # noqa: F841
        ecn = headers.ipv6.ecn  # noqa: F841
        ip_protocol = headers.ipv6.next_header

    # TOR table application order
    acl_ingress_table.apply()
    acl_ingress_qos_table.apply()
    acl_ingress_mirror_and_redirect_table.apply()

    if cancel_copy:
        local_metadata.marked_to_copy = False
