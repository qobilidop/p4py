"""P4Py translation of sai_p4/instantiations/google/wbb.p4 (PLATFORM_BMV2)."""

import p4py.lang as p4
from p4py.arch.v1model import V1Switch
from tests.e2e.sai_p4.fixed.headers import (
    INTERNAL_VLAN_ID,
    NO_VLAN_ID,
    ether_type_t,
    ethernet_addr_t,
    ipv4_addr_t,
    ipv6_addr_t,
    vlan_id_t,
)
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
from tests.e2e.sai_p4.instantiations.google.acl_wbb_ingress import acl_wbb_ingress


@p4.control
def ingress(headers, local_metadata, standard_metadata):
    acl_wbb_ingress.apply(headers, local_metadata, standard_metadata)


@p4.control
def egress(headers, local_metadata, standard_metadata):
    pass


@p4.parser
def packet_parser(
    packet, headers: headers_t, local_metadata: local_metadata_t, standard_metadata
):
    def start():
        return p4.ACCEPT


@p4.deparser
def packet_deparser(packet, headers):
    pass


@p4.control
def verify_ipv4_checksum(headers, local_metadata):
    pass


@p4.control
def compute_ipv4_checksum(headers, local_metadata):
    pass


main = V1Switch(
    parser=packet_parser,
    verify_checksum=verify_ipv4_checksum,
    ingress=ingress,
    egress=egress,
    compute_checksum=compute_ipv4_checksum,
    deparser=packet_deparser,
    sub_controls=(acl_wbb_ingress,),
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
    ),
)
