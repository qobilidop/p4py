"""Protocol and port constants from sai_p4 ids.h and headers.p4."""

import p4py.lang as p4
from tests.e2e.sai_p4.fixed.headers import ether_type_t

# Port constants.
SAI_P4_CPU_PORT = p4.const(p4.bit(9), 510, "SAI_P4_CPU_PORT")

# Ethertype constants.
ETHERTYPE_IPV4 = p4.const(ether_type_t, 0x0800, "ETHERTYPE_IPV4")
ETHERTYPE_IPV6 = p4.const(ether_type_t, 0x86DD, "ETHERTYPE_IPV6")
ETHERTYPE_ARP = p4.const(ether_type_t, 0x0806, "ETHERTYPE_ARP")
ETHERTYPE_8021Q = p4.const(ether_type_t, 0x8100, "ETHERTYPE_8021Q")

# IP protocol constants.
_ip_protocol_t = p4.typedef(p4.bit(8), "ip_protocol_t")
IP_PROTOCOL_ICMP = p4.const(_ip_protocol_t, 0x01, "IP_PROTOCOL_ICMP")
IP_PROTOCOL_IPV4 = p4.const(_ip_protocol_t, 0x04, "IP_PROTOCOL_IPV4")
IP_PROTOCOL_TCP = p4.const(_ip_protocol_t, 0x06, "IP_PROTOCOL_TCP")
IP_PROTOCOL_UDP = p4.const(_ip_protocol_t, 0x11, "IP_PROTOCOL_UDP")
IP_PROTOCOL_IPV6 = p4.const(_ip_protocol_t, 0x29, "IP_PROTOCOL_IPV6")
IP_PROTOCOL_ICMPV6 = p4.const(_ip_protocol_t, 0x3A, "IP_PROTOCOL_ICMPV6")
IP_PROTOCOL_V6_EXTENSION_HOP_BY_HOP = p4.const(
    _ip_protocol_t, 0x00, "IP_PROTOCOL_V6_EXTENSION_HOP_BY_HOP"
)

# BMV2 instance type constants (from v1model standard_metadata).
_instance_type_t = p4.typedef(p4.bit(32), "instance_type_t")
PKT_INSTANCE_TYPE_INGRESS_CLONE = p4.const(
    _instance_type_t, 1, "PKT_INSTANCE_TYPE_INGRESS_CLONE"
)
PKT_INSTANCE_TYPE_EGRESS_CLONE = p4.const(
    _instance_type_t, 2, "PKT_INSTANCE_TYPE_EGRESS_CLONE"
)
PKT_INSTANCE_TYPE_REPLICATION = p4.const(
    _instance_type_t, 5, "PKT_INSTANCE_TYPE_REPLICATION"
)
