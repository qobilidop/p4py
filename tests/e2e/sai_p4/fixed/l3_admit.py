"""P4Py translation of sai_p4/fixed/l3_admit.p4 (PLATFORM_BMV2, TOR)."""

import p4py.lang as p4
from p4py.arch.v1model import standard_metadata_t
from tests.e2e.sai_p4.fixed.metadata import headers_t, local_metadata_t


@p4.control
def admit_google_system_mac(
    headers: p4.inout(headers_t),
    local_metadata: p4.inout(local_metadata_t),
):
    local_metadata.admit_to_l3 = (
        headers.ethernet.dst_addr & p4.hex(0x010000000000)
    ) == 0


@p4.control
def l3_admit(
    headers: p4.inout(headers_t),
    local_metadata: p4.inout(local_metadata_t),
    standard_metadata: p4.inout(standard_metadata_t),
):
    @p4.action
    def admit_to_l3():
        local_metadata.admit_to_l3 = True

    l3_admit_table = p4.table(
        key={
            headers.ethernet.dst_addr: p4.ternary,
            local_metadata.ingress_port: p4.optional,
        },
        actions=[admit_to_l3, p4.NoAction],
        default_action=p4.NoAction,
    )

    if local_metadata.marked_to_drop_by_ingress_vlan_checks:
        local_metadata.admit_to_l3 = False
    else:
        l3_admit_table.apply()
