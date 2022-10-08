from enum import Enum


class PackageType(Enum):
    """Enumeration of the different types of packages."""
    Ethernet2: str = "ETHERNET II"
    Novell_802_3_Raw: int = 1
    IEEE_802_3_LLC: int = 2
    IEEE_802_3_LLC_SNAP: int = 3


EtherTypes = {
    '0200': 'XEROX PUP',
    '0201': 'PUP Addr Trans',
    '0800': 'Internet IP (IPv4)',
    '0801': 'X.75 Internet',
    '0805': 'x.25 Level 3',
    '0806': 'ARP (Address Resolution Protocol)',
    '8035': 'RARP (Reverse Address Resolution Protocol)',
    '809B': 'AppleTalk (Ethertalk)',
    '80F3': 'AARP (AppleTalk Address Resolution Protocol)',
    '8100': 'IEEE 802.1Q VLAN-tagged frames',
    '8137': 'Novell IPX (Internetwork Packet Exchange)',
    '81DD': 'IPv6 (Internet Protocol Version 6)',
    '880B': 'PPP (Point-to-Point Protocol)',
    '8847': 'MPLS (Multi-Protocol Label Switching)',
    '8848': 'MPLS with Upstream Assigment',
    '8863': 'PPPoE Discovery Stage',
    '8864': 'PPPoE Session Stage'
}