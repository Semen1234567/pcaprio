from enum import Enum


class FrameType(Enum):
    """Enumeration of the different types of packages."""
    Ethernet2: str = "ETHERNET II"
    Novell_802_3_Raw: str = "IEEE 802.3 RAW"
    IEEE_802_3_LLC: str = "IEEE 802.3 LLC"
    IEEE_802_3_LLC_SNAP: str = "IEEE 802.3 LLC & SNAP"


class EtherType(Enum):
    """Enumeration of the EtherTypes."""

    XEROX_PUP: str = "XEROX PUP"
    PUP_ADDR_TRANS: str = "PUP Addr Trans"
    IPv4: str = "Internet IP (IPv4)"
    X75_INTERNET: str = "X.75 Internet"
    X25_LEVEL_3: str = "X.25 Level 3"
    ARP: str = "Address Resolution Protocol (ARP)"
    RARP: str = "Reverse Address Resolution Protocol (RARP)"
    APPLE_TALK: str = "AppleTalk"
    AARP: str = "AppleTalk Address Resolution Protocol (AARP)"
    IEEE_802_1Q: str = "IEEE 802.1Q VLAN-tagged frames"
    NOVELL_IPX: str = "Novell Internetwork Packet Exchange (IPX)"
    IPv6: str = "Internet Protocol Version 6 (IPv6)"
    PPP: str = "Point-to-Point Protocol (PPP)"
    MPLS: str = "Multiprotocol Label Switching (MPLS)"
    MPLS_WITH_UPSTREAM_ASSIGMENT: str = "Multiprotocol Label Switching (MPLS) with Upstream Assigment"
    PPPoE_DISCOVERY_STAGE: str = "PPPoE Discovery Stage"
    PPPoE_SESSION_STAGE: str = "PPPoE Session Stage"

    CDP: str = "CDP" # Cisco Discovery Protocol
    DTP: str = "DTP" # Dynamic Trunking Protocol
    PVSTP_PLUS: str = "PVSTP+" # Per-VLAN Spanning Tree Plus

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