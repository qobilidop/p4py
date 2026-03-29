"""P4Py translation of sai_p4/fixed/vlan.p4 (PLATFORM_BMV2)."""

import p4py.lang as p4
from p4py.arch import v1model
from tests.e2e.sai_p4.fixed.headers import INTERNAL_VLAN_ID, NO_VLAN_ID
from tests.e2e.sai_p4.fixed.ids import (
    ETHERTYPE_8021Q,
    PKT_INSTANCE_TYPE_EGRESS_CLONE,
    PKT_INSTANCE_TYPE_INGRESS_CLONE,
)


@p4.control
def vlan_untag(headers, local_metadata, standard_metadata):
    @p4.action
    def disable_vlan_checks():
        local_metadata.enable_vlan_checks = False

    disable_vlan_checks_table = p4.table(
        key={p4.literal(1, width=1): p4.ternary},
        actions=[disable_vlan_checks],
        size=1,
    )

    if headers.vlan.isValid():
        local_metadata.vlan_id = headers.vlan.vlan_id
        headers.ethernet.ether_type = headers.vlan.ether_type
        headers.vlan.setInvalid()
        local_metadata.input_packet_is_vlan_tagged = True
    else:
        local_metadata.vlan_id = INTERNAL_VLAN_ID

    local_metadata.enable_vlan_checks = True
    disable_vlan_checks_table.apply()


@p4.control
def ingress_vlan_checks(headers, local_metadata, standard_metadata):
    enable_ingress_vlan_checks = p4.bool_(True)
    ingress_port_is_member_of_vlan = p4.bool_(False)

    @p4.action
    def disable_ingress_vlan_checks():
        enable_ingress_vlan_checks = False  # noqa: F841

    disable_ingress_vlan_checks_table = p4.table(
        key={p4.literal(1, width=1): p4.lpm},
        actions=[disable_ingress_vlan_checks],
        size=1,
    )

    disable_ingress_vlan_checks_table.apply()
    if (
        local_metadata.enable_vlan_checks
        and enable_ingress_vlan_checks
        and not ingress_port_is_member_of_vlan
        and not (
            local_metadata.vlan_id == NO_VLAN_ID
            or local_metadata.vlan_id == INTERNAL_VLAN_ID
        )
    ):
        local_metadata.marked_to_drop_by_ingress_vlan_checks = True
        v1model.mark_to_drop(standard_metadata)


@p4.control
def egress_vlan_checks(headers, local_metadata, standard_metadata):
    port = p4.bit(9)
    egress_port_is_member_of_vlan = p4.bool_(False)
    enable_egress_vlan_checks = p4.bool_(True)

    @p4.action
    def disable_egress_vlan_checks():
        enable_egress_vlan_checks = False  # noqa: F841

    @p4.action
    def no_action():
        pass

    @p4.action
    def make_tagged_member():
        egress_port_is_member_of_vlan = True  # noqa: F841

    @p4.action
    def make_untagged_member():
        egress_port_is_member_of_vlan = True  # noqa: F841
        local_metadata.omit_vlan_tag_on_egress_packet = True

    disable_egress_vlan_checks_table = p4.table(
        key={p4.literal(1, width=1): p4.lpm},
        actions=[disable_egress_vlan_checks],
        size=1,
    )

    vlan_table = p4.table(
        key={local_metadata.vlan_id: p4.exact},
        actions=[no_action],
    )

    vlan_membership_table = p4.table(
        key={
            local_metadata.vlan_id: p4.exact,
            port: p4.exact,
        },
        actions=[make_tagged_member, make_untagged_member, p4.NoAction],
        default_action=p4.NoAction,
    )

    disable_egress_vlan_checks_table.apply()
    vlan_table.apply()
    if not (
        standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE
    ) and not (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE):
        vlan_membership_table.apply()
        if (
            local_metadata.enable_vlan_checks
            and enable_egress_vlan_checks
            and not egress_port_is_member_of_vlan
            and not (
                local_metadata.vlan_id == NO_VLAN_ID
                or local_metadata.vlan_id == INTERNAL_VLAN_ID
            )
        ):
            v1model.mark_to_drop(standard_metadata)


@p4.control
def vlan_tag(headers, local_metadata, standard_metadata):
    if (
        not (
            local_metadata.vlan_id == NO_VLAN_ID
            or local_metadata.vlan_id == INTERNAL_VLAN_ID
        )
        and not (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE)
        and not local_metadata.omit_vlan_tag_on_egress_packet
    ):
        headers.vlan.setValid()
        headers.vlan.priority_code_point = 0
        headers.vlan.drop_eligible_indicator = 0
        headers.vlan.vlan_id = local_metadata.vlan_id
        headers.vlan.ether_type = headers.ethernet.ether_type
        headers.ethernet.ether_type = ETHERTYPE_8021Q
