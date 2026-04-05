"""P4Py translation of sai_p4/fixed/packet_io.p4 (PLATFORM_BMV2)."""

import p4py.lang as p4
from p4py.arch.v1model import standard_metadata_t
from tests.e2e.sai_p4.fixed.metadata import headers_t, local_metadata_t


@p4.control
def packet_out_decap(
    headers: p4.inout(headers_t),
    local_metadata: p4.inout(local_metadata_t),
    standard_metadata: p4.inout(standard_metadata_t),
):
    if (
        headers.packet_out_header.isValid()
        and headers.packet_out_header.submit_to_ingress == 0
    ):
        standard_metadata.egress_spec = p4.cast(
            p4.bit(9), headers.packet_out_header.egress_port
        )
        local_metadata.bypass_ingress = True
    headers.packet_out_header.setInvalid()
