"""P4Py translation of sai_p4/fixed/packet_io.p4 (PLATFORM_BMV2)."""

import p4py.lang as p4


@p4.control
def packet_out_decap(headers, local_metadata, standard_metadata):
    if (
        headers.packet_out_header.isValid()
        and headers.packet_out_header.submit_to_ingress == 0
    ):
        standard_metadata.egress_spec = p4.cast(
            p4.bit(9), headers.packet_out_header.egress_port
        )
        local_metadata.bypass_ingress = True
    headers.packet_out_header.setInvalid()
