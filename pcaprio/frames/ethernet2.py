import binascii

from dataclasses import dataclass
from dataclasses import field

from .base import PCAPFrame
from .types import EthernetSide

from ..utils import repr_IPv4, repr_IPv6
from ..enumerations import CommunicationProtocol
from ..enumerations import communication_protocols
from ..enumerations import TCPAppProtocol
from ..enumerations import tcp_app_ports
from ..enumerations import udp_app_ports
from ..enumerations import UDPAppProtocol
from ..enumerations import FrameType
from ..enumerations import EtherTypes
from ..enumerations import EtherType
from ..enumerations import icmp_types
from ..enumerations import arp_opcodes
from ..enumerations import ARPOpcode


@dataclass
class Ethernet2Frame(PCAPFrame):
    destination: EthernetSide
    source: EthernetSide
    data: bytes
    ether_type: EtherTypes = field(default=None)
    isl: bytes = field(repr=False, default=None)

    communication_protocol: CommunicationProtocol = field(default=None)

    ether_type_code: str = field(repr=False, default=None)
    raw: bytes = field(repr=False, default=None)
    frame_type: FrameType = FrameType.Ethernet2

    def __post_init__(self) -> None:
        self.ether_type_code = self.ether_type_code.upper()
        self.ether_type = EtherTypes.get(self.ether_type_code, EtherType.UNKNOWN)

        self._get_source_and_destination_ip()
    
    @property
    def icmp_type(self) -> str | None:
        if self.communication_protocol == CommunicationProtocol.ICMP:
            return icmp_types.get((self.raw[34], self.raw[35]), "UNKNOWN")
    
    @property
    def icmp_data(self) -> bytes | None:
        if self.communication_protocol == CommunicationProtocol.ICMP:
            return self.raw[42:]
    
    @property
    def icmp_checksum(self) -> int:
        if self.communication_protocol == CommunicationProtocol.ICMP:
            return int.from_bytes(self.raw[36:38], byteorder='big')

    @property
    def icmp_identifier(self) -> int:
        if self.communication_protocol == CommunicationProtocol.ICMP:
            return int.from_bytes(self.raw[38:40], byteorder='big')
    
    @property
    def icmp_sequence_number(self) -> int:
        if self.communication_protocol == CommunicationProtocol.ICMP:
            return int.from_bytes(self.raw[40:42], byteorder='big')
    
    @property
    def TCP_flag(self) -> int:
        if self.communication_protocol == CommunicationProtocol.TCP:
            flag = int.from_bytes(self.raw[47:48], byteorder='big')
            return flag
        return 0
    
    @property
    def seglen(self) -> int:
        if self.communication_protocol == CommunicationProtocol.TCP:
            return len(self.raw[54:])
        return 0
    
    @property
    def ip_id(self) -> int:
        if self.ether_type == EtherType.IPv4:
            return int.from_bytes(self.raw[18:20], byteorder='big')
        return 0
    
    @property
    def sequence_number(self) -> int:
        if self.communication_protocol == CommunicationProtocol.TCP:
            return int.from_bytes(self.raw[38:42], byteorder='big')
        return 0
    
    @property
    def fragment_offset(self) -> int:
        if self.ether_type == EtherType.IPv4:
            return int.from_bytes(self.raw[20:22], byteorder='big') & 0x1FFF
        return -1
    
    @property
    def more_fragments(self) -> bool:
        if self.ether_type == EtherType.IPv4:
            return bool(int.from_bytes(self.raw[20:22], byteorder='big') & 0x2000)
        return False
    
    @property
    def arp_opcode(self) -> str | None:
        if self.ether_type == EtherType.ARP:
            return arp_opcodes.get(int.from_bytes(self.raw[20:22], byteorder='big'), ARPOpcode.UNKNOWN)
        
    def _get_source_and_destination_ip(self) -> None:
        match self.ether_type:
            case EtherType.IPv4:
                self.source.ip = repr_IPv4(self.raw[26:30])
                self.destination.ip = repr_IPv4(self.raw[30:34])

                self._get_communication_protocol_ipv4()

                if self.communication_protocol in [CommunicationProtocol.TCP, CommunicationProtocol.UDP]:
                    self.source.port = int.from_bytes(self.raw[34:36], byteorder='big')
                    self.destination.port = int.from_bytes(self.raw[36:38], byteorder='big')
                
                if self.communication_protocol == CommunicationProtocol.ICMP:
                    ...

                self._identify_app_by_port()
            
            case EtherType.IPv6:
                self.source.ip = repr_IPv6(self.raw[22:38])
                self.destination.ip = repr_IPv6(self.raw[38:54])
            
            case EtherType.ARP:
                self.source.ip = repr_IPv4(self.raw[28:32])
                self.destination.ip = repr_IPv4(self.raw[38:42])
    
    def _get_communication_protocol_ipv4(self) -> None:
        self.communication_protocol = communication_protocols.get(self.raw[23], CommunicationProtocol.UNKNOWN)
    
    def _identify_app_by_port(self) -> None:
        if self.communication_protocol == CommunicationProtocol.TCP:
            self.source.app = tcp_app_ports.get(self.source.port, TCPAppProtocol.UNKNOWN) 
            self.destination.app = tcp_app_ports.get(self.destination.port, TCPAppProtocol.UNKNOWN)
        
        elif self.communication_protocol == CommunicationProtocol.UDP:
            self.source.app = udp_app_ports.get(self.source.port, UDPAppProtocol.UNKNOWN) 
            self.destination.app = udp_app_ports.get(self.destination.port, UDPAppProtocol.UNKNOWN)
    
    @property
    def hexlify_data(self) -> str:
        return binascii.hexlify(self.data).decode('utf-8').upper()
