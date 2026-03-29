"""P4Py translation of sai_p4/instantiations/google/acl_wbb_ingress.p4."""

import p4py.lang as p4
from p4py.arch import v1model
from p4py.arch.v1model import standard_metadata_t

from tests.e2e.sai_p4.fixed.metadata import MeterColor_t, headers_t, local_metadata_t

COPY_TO_CPU_SESSION_ID = 255


@p4.control
def acl_wbb_ingress(
    headers: p4.in_(headers_t),
    local_metadata: p4.inout(local_metadata_t),
    standard_metadata: p4.inout(standard_metadata_t),
):
    ttl = p4.bit(8)

    acl_wbb_ingress_meter = v1model.direct_meter(MeterColor_t, "bytes")
    acl_wbb_ingress_counter = v1model.direct_counter("packets_and_bytes")

    @p4.action
    def acl_wbb_ingress_copy():
        acl_wbb_ingress_meter.read(local_metadata.color)
        v1model.clone(v1model.CloneType.I2E, COPY_TO_CPU_SESSION_ID)
        acl_wbb_ingress_counter.count()

    @p4.action
    def acl_wbb_ingress_trap():
        acl_wbb_ingress_meter.read(local_metadata.color)
        v1model.clone(v1model.CloneType.I2E, COPY_TO_CPU_SESSION_ID)
        v1model.mark_to_drop(standard_metadata)
        acl_wbb_ingress_counter.count()

    acl_wbb_ingress_table = p4.table(
        key={
            headers.ipv4.isValid(): p4.optional,
            headers.ipv6.isValid(): p4.optional,
            headers.ethernet.ether_type: p4.ternary,
            ttl: p4.ternary,
        },
        actions=[acl_wbb_ingress_copy, acl_wbb_ingress_trap, p4.NoAction],
        default_action=p4.NoAction,
        meters=acl_wbb_ingress_meter,
        counters=acl_wbb_ingress_counter,
        size=8,
    )

    if headers.ipv4.isValid():
        ttl = headers.ipv4.ttl
    elif headers.ipv6.isValid():
        ttl = headers.ipv6.hop_limit

    acl_wbb_ingress_table.apply()
