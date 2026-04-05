"""P4Py translation of sai_p4/instantiations/google/acl_pre_ingress.p4 (TOR)."""

import p4py.lang as p4
from p4py.arch import v1model
from p4py.arch.v1model import standard_metadata_t
from tests.e2e.sai_p4.fixed.headers import vlan_id_t
from tests.e2e.sai_p4.fixed.metadata import (
    acl_metadata_t,
    headers_t,
    local_metadata_t,
    vrf_id_t,
)


@p4.control
def acl_pre_ingress(
    headers: p4.in_(headers_t),
    local_metadata: p4.inout(local_metadata_t),
    standard_metadata: p4.in_(standard_metadata_t),
):
    # First 6 bits of IPv4 TOS or IPv6 traffic class (or 0, for non-IP packets)
    dscp = p4.bit(6)
    # Last 2 bits of IPv4 TOS or IPv6 traffic class (or 0, for non-IP packets)
    ecn = p4.bit(2)
    # IPv4 IP protocol or IPv6 next_header (or 0, for non-IP packets)
    ip_protocol = p4.bit(8)

    set_outer_vlan_id_action_applied = p4.bool_(False)
    set_outer_vlan_id_action_vlan_id = p4.bit(12)

    acl_pre_ingress_counter = v1model.direct_counter("packets_and_bytes")
    acl_pre_ingress_vlan_counter = v1model.direct_counter("packets_and_bytes")
    acl_pre_ingress_metadata_counter = v1model.direct_counter("packets_and_bytes")

    @p4.action
    def set_vrf(vrf_id: vrf_id_t):
        local_metadata.vrf_id = vrf_id
        acl_pre_ingress_counter.count()

    @p4.action
    def set_outer_vlan_id(vlan_id: vlan_id_t):
        set_outer_vlan_id_action_applied = True  # noqa: F841
        set_outer_vlan_id_action_vlan_id = vlan_id  # noqa: F841
        acl_pre_ingress_vlan_counter.count()

    @p4.action
    def set_acl_metadata(acl_metadata: acl_metadata_t):
        local_metadata.acl_metadata = acl_metadata
        acl_pre_ingress_metadata_counter.count()

    @p4.action
    def set_outer_vlan_id_and_acl_metadata(
        vlan_id: vlan_id_t, acl_metadata: acl_metadata_t
    ):
        set_outer_vlan_id_action_applied = True  # noqa: F841
        set_outer_vlan_id_action_vlan_id = vlan_id  # noqa: F841
        local_metadata.acl_metadata = acl_metadata
        acl_pre_ingress_vlan_counter.count()

    # TOR key: no dst_mac (that's FBR only)
    acl_pre_ingress_table = p4.table(
        key={
            headers.ipv4.isValid() or headers.ipv6.isValid(): p4.optional,
            headers.ipv4.isValid(): p4.optional,
            headers.ipv6.isValid(): p4.optional,
            headers.ethernet.src_addr: p4.ternary,
            headers.ipv4.dst_addr: p4.ternary,
            headers.ipv6.dst_addr[127:64]: p4.ternary,
            dscp: p4.ternary,
            ecn: p4.ternary,
            local_metadata.ingress_port: p4.optional,
        },
        actions=[set_vrf, p4.NoAction],
        default_action=p4.NoAction,
        counters=acl_pre_ingress_counter,
    )

    acl_pre_ingress_vlan_table = p4.table(
        key={
            headers.ipv4.isValid() or headers.ipv6.isValid(): p4.optional,
            headers.ipv4.isValid(): p4.optional,
            headers.ipv6.isValid(): p4.optional,
            headers.ethernet.ether_type: p4.ternary,
            local_metadata.vlan_id: p4.ternary,
        },
        actions=[set_outer_vlan_id, set_outer_vlan_id_and_acl_metadata, p4.NoAction],
        default_action=p4.NoAction,
        counters=acl_pre_ingress_vlan_counter,
    )

    # TOR metadata table keys: includes icmpv6_type, dscp, ecn, in_port
    acl_pre_ingress_metadata_table = p4.table(
        key={
            headers.ipv4.isValid() or headers.ipv6.isValid(): p4.optional,
            headers.ipv4.isValid(): p4.optional,
            headers.ipv6.isValid(): p4.optional,
            ip_protocol: p4.ternary,
            local_metadata.l4_dst_port: p4.ternary,
            headers.icmp.type: p4.ternary,
            dscp: p4.ternary,
            ecn: p4.ternary,
            local_metadata.ingress_port: p4.optional,
        },
        actions=[set_acl_metadata, set_outer_vlan_id, p4.NoAction],
        default_action=p4.NoAction,
        counters=acl_pre_ingress_metadata_counter,
    )

    # Apply block
    if headers.ipv4.isValid():
        dscp = headers.ipv4.dscp
        ecn = headers.ipv4.ecn
        ip_protocol = headers.ipv4.protocol
    elif headers.ipv6.isValid():
        dscp = headers.ipv6.dscp
        ecn = headers.ipv6.ecn
        if (
            headers.ipv6.next_header == 0
            and headers.hop_by_hop_options.isValid()
        ):
            ip_protocol = headers.hop_by_hop_options.next_header
        else:
            ip_protocol = headers.ipv6.next_header

    # TOR table application order
    acl_pre_ingress_vlan_table.apply()
    acl_pre_ingress_metadata_table.apply()
    acl_pre_ingress_table.apply()

    # The SET_OUTER_VLAN_ID action affects the packet if and only if the input
    # packet is VLAN tagged.
    if (
        set_outer_vlan_id_action_applied
        and local_metadata.input_packet_is_vlan_tagged
    ):
        local_metadata.vlan_id = set_outer_vlan_id_action_vlan_id
