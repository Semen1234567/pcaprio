import binascii


from dataclasses import dataclass, field
from .frames_types import Ethernet2Frame, identify_frame
from .frames_types import PCAPFrame
from .enumerations import EtherTypes



@dataclass
class PCAPPacket:
    timestamp1: int
    timestamp2: int
    incl_len: int
    orig_len: int
    data: bytes
    

    raw: bytes = field(repr=False, default=None)
    frame: PCAPFrame = field(default=None)

    @property
    def hexlify_data(self) -> str:
        return binascii.hexlify(self.data).decode('utf-8')
    
    @property
    def medium_len(self) -> len:
        """IDK what this is, but my frieds seds m"""
    

    def parse(self) -> None:
        self.frame = identify_frame(self.data)
    
    def _parse_default(self) -> None:
        destination_mac = self.hexlify_data[0:12]
        source_mac = self.hexlify_data[12:24]
        
        destination_mac = ':'.join(destination_mac[i:i+2] for i in range(0, len(destination_mac), 2))
        source_mac = ':'.join(source_mac[i:i+2] for i in range(0, len(source_mac), 2))

        return PCAPFrame(
            destination_mac=destination_mac,
            source_mac=source_mac
        )
    
    def _parse_packet_like_ethernet(self) -> Ethernet2Frame | None:
        destination_mac = self.hexlify_data[0:12]
        source_mac = self.hexlify_data[12:24]
        ethertype = self.hexlify_data[24:28]

        if ethertype not in EtherTypes:
            return False
        
        ethertype_name = EtherTypes[ethertype]

        data = self.data[14:]

        destination_mac = ':'.join(destination_mac[i:i+2] for i in range(0, len(destination_mac), 2))
        source_mac = ':'.join(source_mac[i:i+2] for i in range(0, len(source_mac), 2))
        
        return Ethernet2Frame(
            destination_mac=destination_mac,
            source_mac=source_mac,
            ether_type=ethertype_name,
            data=data
        )
    
    def __dict__(self) -> dict:
        return {
            'timestamp1': self.timestamp1,
            'timestamp2': self.timestamp2,
            'incl_len': self.incl_len,
            'orig_len': self.orig_len,
            'data': self.hexlify_data,
            'frame': self.frame
        }
