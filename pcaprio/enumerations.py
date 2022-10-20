from enum import Enum


class FrameType(Enum):
    """Enumeration of the different types of packages."""

    Ethernet2: str = "ETHERNET II"
    Novell_802_3_Raw: str = "IEEE 802.3 RAW"
    IEEE_802_3_LLC: str = "IEEE 802.3 LLC"
    IEEE_802_3_LLC_SNAP: str = "IEEE 802.3 LLC & SNAP"


class ARPOpcode(Enum):
    """Enumeration of the different types of ARP packages."""

    REQUEST: str = "ARP Request"
    REPLY: str = "ARP Reply"
    RARP_REQUEST: str = "RARP Request"
    RARP_REPLY: str = "RARP Reply"
    DRARP_REQUEST: str = "DRARP Request"
    DRARP_REPLY: str = "DRARP Reply"
    DRARP_ERROR: str = "DRARP Error"
    INARP_REQUEST: str = "InARP Request"
    INARP_REPLY: str = "InARP Reply"
    ARP_NAK: str = "ARP NAK"

    UNKNOWN: str = "UNKNOWN"

arp_opcodes = {
    1: ARPOpcode.REQUEST,
    2: ARPOpcode.REPLY,
    3: ARPOpcode.RARP_REQUEST,
    4: ARPOpcode.RARP_REPLY,
    5: ARPOpcode.DRARP_REQUEST,
    6: ARPOpcode.DRARP_REPLY,
    7: ARPOpcode.DRARP_ERROR,
    8: ARPOpcode.INARP_REQUEST,
    9: ARPOpcode.INARP_REPLY,
    10: ARPOpcode.ARP_NAK,
}


icmp_types = {
    (0, 0): "Echo Reply",
    (3, 0): "Destination Network Unreachable",
    (3, 1): "Destination Host Unreachable",
    (3, 2): "Destination Protocol Unreachable",
    (3, 3): "Destination Port Unreachable",
    (3, 4): "Fragmentation Needed and Don't Fragment was Set",
    (3, 5): "Source Route Failed",
    (3, 6): "Destination Network Unknown",
    (3, 7): "Destination Host Unknown",
    (3, 8): "Source Host Isolated",
    (3, 9): "Destination Network Administratively Prohibited",
    (3, 10): "Destination Host Administratively Prohibited",
    (3, 11): "Network Unreachable for Type of Service",
    (3, 12): "Host Unreachable for Type of Service",
    (3, 13): "Communication Administratively Prohibited by Filtering",
    (4, 0): "Source Quench",
    (5, 0): "Redirect Datagram for the Network",
    (5, 1): "Redirect Datagram for the Host",
    (5, 2): "Redirect Datagram for the Type of Service and Network",
    (5, 3): "Redirect Datagram for the Type of Service and Host",
    (7, 19): "Host Unreachable for Fragmentation",
    (8, 0): "Echo Request",
    (9, 0): "Router Advertisement",
    (10, 0): "Router Solicitation",
    (11, 0): "Time Exceeded for Transit",
    (11, 1): "Fragment Reassembly Time Exceeded",
    (12, 0): "Pointer indicates the error",
    (12, 1): "Missing a Required Option",
    (12, 2): "Bad Length",
    (13, 0): "Timestamp",
    (14, 0): "Timestamp Reply",
    (15, 0): "Information Request",
    (16, 0): "Information Reply",
    (17, 0): "Address Mask Request",
    (18, 0): "Address Mask Reply",
    (30, 0): "Traceroute",
    (97, 98): "Experimental Measurement",
    (68, 36): "Mobile Host Redirect",

}


class TCPFlag:
    """Enumeration of the different types of TCP flags."""
    SYN: int = 0x02
    ACK: int = 0x10
    RST: int = 0x04
    FIN: int = 0x01
    PSH: int = 0x08
    
    UNKNOWN: int = 0x00


class AppProtocol: ...

class TCPAppProtocol(AppProtocol, Enum):
    ECHO: str = "ECHO"
    CHARGEB: str = "CHARGEN"
    SSH: str = "SSH"
    HTTP: str = "HTTP"
    HTTPS: str = "HTTPS"
    DNS: str = "DNS"
    POP3: str = "POP3"
    NNTP: str = "NNTP"
    FTP_DATA: str = "FTP-DATA"
    FTP_CONTROL: str = "FTP-CONTROL"
    TELNET: str = "TELNET"
    SMTP: str = "SMTP"
    NETBIOS_SSN: str = "NETBIOS-SSN"
    IMAP: str = "IMAP"
    BGP: str = "BGP"
    LDAP: str = "LDAP"
    TIME: str = "TIME"
    DHCP: str = "DHCP"
    NETBIOS_NS: str = "NETBIOS-NS"
    NETBIOS_DGM: str = "NETBIOS-DGM"
    SNMP: str = "SNMP"
    SNMP_TRAP: str = "SNMP-TRAP"
    SYSLOG: str = "SYSLOG"
    RIP: str = "RIP"
    TRACEROUTE: str = "TRACEROUTE"
    FINGER: str = "FINGER"
    SUNRPC: str = "SUNRPC"
    MICROSOFT_DS: str = "MICROSOFT-DS"
    SOCKS: str = "SOCKS"

    UNKNOWN: str = "UNKNOWN"

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN

class UDPAppProtocol(AppProtocol, Enum):
    TFTP: str = "TFTP"
    
    UNKNOWN: str = "UNKNOWN"
    
    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


tcp_app_ports = {
    7: TCPAppProtocol.ECHO,
    19: TCPAppProtocol.CHARGEB,
    20: TCPAppProtocol.FTP_DATA,
    21: TCPAppProtocol.FTP_CONTROL,
    22: TCPAppProtocol.SSH,
    23: TCPAppProtocol.TELNET,
    25: TCPAppProtocol.SMTP,
    37: TCPAppProtocol.TIME,
    53: TCPAppProtocol.DNS,
    67: TCPAppProtocol.DHCP,
    79: TCPAppProtocol.FINGER,
    80: TCPAppProtocol.HTTP,
    110: TCPAppProtocol.POP3,
    111: TCPAppProtocol.SUNRPC,
    119: TCPAppProtocol.NNTP,
    137: TCPAppProtocol.NETBIOS_NS,
    138: TCPAppProtocol.NETBIOS_DGM,
    139: TCPAppProtocol.NETBIOS_SSN,
    143: TCPAppProtocol.IMAP,
    161: TCPAppProtocol.SNMP,
    162: TCPAppProtocol.SNMP_TRAP,
    179: TCPAppProtocol.BGP,
    389: TCPAppProtocol.LDAP,
    443: TCPAppProtocol.HTTPS,
    445: TCPAppProtocol.MICROSOFT_DS,
    514: TCPAppProtocol.SYSLOG,
    520: TCPAppProtocol.RIP,
    1080: TCPAppProtocol.SOCKS,
    33434: TCPAppProtocol.TRACEROUTE,

    -1: TCPAppProtocol.UNKNOWN
}

udp_app_ports = {
    69: UDPAppProtocol.TFTP,
    
    -1: TCPAppProtocol.UNKNOWN
}


class CommunicationProtocol(Enum):
    TCP: str = "TCP"
    UDP: str = "UDP"
    IGMP: str = "IGMP"
    ICMP: str = "ICMP"
    PIM: str = "PIM"

    UNKNOWN: str = "Unknown"


communication_protocols = {
    6: CommunicationProtocol.TCP,
    17: CommunicationProtocol.UDP,
    1: CommunicationProtocol.ICMP,
    2: CommunicationProtocol.IGMP,
    103: CommunicationProtocol.PIM
}


class EtherType(Enum):
    """
    Enumeration of the EtherTypes.
    FROM: https://telecomworld101.com/EthernetType.html
    """

    XEROX_PUP: str = "XEROX PUP"
    PUP_ADDR_TRANS: str = "PUP Addr Trans"
    IPv4: str = "IPv4"
    X75_INTERNET: str = "X.75 Internet"
    X25_LEVEL_3: str = "X.25 Level 3"
    ARP: str = "ARP" # Address Resolution Protocol
    RARP: str = "RARP" # Reverse Address Resolution Protocol
    APPLE_TALK: str = "AppleTalk"
    AARP: str = "AARP" # AppleTalk Address Resolution Protocol
    IEEE_802_1Q: str = "IEEE 802.1Q VLAN-tagged frames"
    NOVELL_IPX: str = "Novell Internetwork Packet Exchange (IPX)"
    IPv6: str = "IPv6"
    PPP: str = "Point-to-Point Protocol (PPP)"
    MPLS: str = "Multiprotocol Label Switching (MPLS)"
    MPLS_WITH_UPSTREAM_ASSIGMENT: str = "Multiprotocol Label Switching (MPLS) with Upstream Assigment"
    PPPoE_DISCOVERY_STAGE: str = "PPPoE Discovery Stage"
    PPPoE_SESSION_STAGE: str = "PPPoE Session Stage"

    CDP: str = "CDP" # Cisco Discovery Protocol
    DTP: str = "DTP" # Dynamic Trunking Protocol
    PVSTP_PLUS: str = "PVSTP+" # Per-VLAN Spanning Tree Plus
    ECTP: str = "ECTP" # Loopback
    LLDP: str = "LLDP" # Link Layer Discovery Protocol

    UNKNOWN: str = "Unknown"


EtherTypes = {
    '0200': EtherType.XEROX_PUP,
    '0201': EtherType.PUP_ADDR_TRANS,
    '0800': EtherType.IPv4,
    '0801': EtherType.X75_INTERNET,
    '0805': EtherType.X25_LEVEL_3,
    '0806': EtherType.ARP,
    '8035': EtherType.RARP,
    '809B': EtherType.APPLE_TALK,
    '80F3': EtherType.AARP,
    '8100': EtherType.IEEE_802_1Q,
    '8137': EtherType.NOVELL_IPX,
    '86DD': EtherType.IPv6,
    '880B': EtherType.PPP,
    '8847': EtherType.MPLS,
    '8848': EtherType.MPLS_WITH_UPSTREAM_ASSIGMENT,
    '8863': EtherType.PPPoE_DISCOVERY_STAGE,
    '8864': EtherType.PPPoE_SESSION_STAGE,


    '2000': EtherType.CDP,
    '2004': EtherType.DTP,
    '010B': EtherType.PVSTP_PLUS,
    '9000': EtherType.ECTP,
    '88CC': EtherType.LLDP,
    
    
}


class IEEE_SAP(Enum):
    """Enumeration of the IEEE SAPs."""

    NULL: str = "Null"
    LLC_SM_I: str = "LLC Sublayer Management / Individual"
    LLC_SM_G: str = "LLC Sublayer Management / Group"
    IP: str = "IP (DoD Internet Protocol)"
    PROWAY_NETWORK_MANAGEMENT: str = "PROWAY (IEC 955) Network Management, Maintenance and Installation"
    MMS: str = "Manufacturing Message Specification (MMS)"
    ISI_IP: str = "ISI IP"
    X25_PLP: str = "X.25 Packet Layer Protocol (PLP)"
    PROWAY_ACTIVE_STATION_LIST_MAITENANCE: str = "PROWAY (IEC 955) Active Station List Maintenance"
    SNAP: str = "SNAP (Subnetwork Access Protocol / non-IEEE SAPs)"
    IPX: str = "IPX" # Novell IPX
    LAN_MANAGMENT: str = "LAN Management"
    ISO: str = "ISO Network Layer Protocol"
    GLOBAL_DSAP: str = "Global DSAP"
    
    NETBIOS: str = "NetBIOS"
    STP: str = "STP" # Spanning Tree Protocol
    
    UNKNOWN: str = "Unknown"


IEEE_SAPs = {
    '00': IEEE_SAP.NULL,
    '02': IEEE_SAP.LLC_SM_I,
    '03': IEEE_SAP.LLC_SM_G,
    '06': IEEE_SAP.IP,
    '0E': IEEE_SAP.PROWAY_NETWORK_MANAGEMENT,
    '42': IEEE_SAP.STP,
    '4E': IEEE_SAP.MMS,
    '5E': IEEE_SAP.ISI_IP,
    '7E': IEEE_SAP.X25_PLP,
    '8E': IEEE_SAP.PROWAY_ACTIVE_STATION_LIST_MAITENANCE,
    'AA': IEEE_SAP.SNAP,
    'E0': IEEE_SAP.IPX,
    'F4': IEEE_SAP.LAN_MANAGMENT,
    'FE': IEEE_SAP.ISO,
    'FF': IEEE_SAP.GLOBAL_DSAP,
    'F0': IEEE_SAP.NETBIOS,
}