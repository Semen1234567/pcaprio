import binascii


from dataclasses import dataclass
from dataclasses import field
from typing import Generator
from .pcap_frames import Ethernet2Frame, IEEE_802_3_LLC_SNAP_Frame
from .pcap_frames import IEEE_802_3_LLC_Frame
from .pcap_frames import identify_frame
from .pcap_frames import PCAPFrame
from .enumerations import TCPAppProtocol, EtherType, FrameType
from .utils import beautiful_hex

def frame_number_gen() -> Generator[int, None, None]:
    index = 1
    while True:
        yield index
        index += 1

fnum = frame_number_gen()

@dataclass
class PCAPPacket:
    timestamp1: int
    timestamp2: int
    incl_len: int
    orig_len: int
    data: bytes

    raw: bytes = field(repr=False, default=None)
    frame: PCAPFrame = field(default=None)
    frame_number: int = field(init=False, default=-1)


    @property
    def hexlify_data(self) -> str:
        return binascii.hexlify(self.data).decode('utf-8').upper()
    
    @property
    def beautiful_hexlify_data(self) -> str:
        return beautiful_hex(self.hexlify_data)
    
    @property
    def medium_len(self) -> len:
        """
                     _________________________________________
                    / IDK, my friends said it works like this \\
                    \\                                        /
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠶⠛⠉⠉⠉⠉⢟⡒⠲⠤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠋⠁⠀⠀⠀⠀⠀⣴⣟⣹⣗⡀⠈⠙⢶⡄⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⢀⠀⣀⣀⣀⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⢁⣤⡄⠀⠀⠀⠀⠀⠀⢸⡋⣿⡿⣷⠀⠀⠙⢦⡀⣠⠞⠋⠉⠛⢦⡀⠀⠀⢀⣴⢿⣿⣿⡿⠿⢟⡓⣦
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣯⣴⢤⡄⠀⠀⠀⠀⠀⠘⠷⡼⠿⠃⠀⠀⠀⠈⢿⠇⠀⠀⠀⠀⠀⠻⣆⠀⠸⣧⢸⣿⡷⢶⡟⠉⠙⠛
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⢸⠫⣿⢰⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⢹⡆⠀⢹⡟⠉⠀⠀⢿⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⠈⠓⠚⠋⠀⠀⠀⠀⠀⠀⠀⣆⠀⠀⠀⠀⠀⠀⠀⠀⢿⠀⠀⠀⠀⠀⠀⠀⢻⡀⠀⢿⡀⠀⠀⠈⣧⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⠋⠉⠓⠶⣼⡇⠀⠀⠀⠀⠀⢷⣄⣠⠴⠖⠛⠻⠆⠀⠀⠀⠀⠀⠀⠀⢸⡆⠀⢀⠀⠀⠀⠀⠈⣧⠀⠈⣧⠀⠀⠀⢹⡄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⠀⠀⠀⠘⢿⡄⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠈⢧⠀⠀⠀⠀⠘⣇⠀⣿⠀⠀⠀⠀⣧⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠀⠀⠀⠀⠀⠀⠀⠀⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠁⠀⠀⠸⡆⠀⠀⠀⠀⠹⣄⡿⠀⠀⠀⠀⣽⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⡀⠀⠀⠙⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⠃⠀⠀⠀⠀⠻⣦⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⡏⠀
⠀⠀⠀⠀⠀⠀⣰⣟⣇⠈⢻⡄⠀⠀⠀⢿⠀⠀⠀⠀⠀⠀⣇⠀⠀⠀⠈⠛⠦⢤⣀⣀⡀⠀⠀⠀⠀⠀⠀⣀⣠⠶⠋⠀⠀⠀⠀⠀⠀⠀⢸⢳⣄⠀⠀⠀⠀⠀⠀⠀⣸⠇⠀
⠀⠀⠀⣀⣤⣿⠷⠋⠙⠂⠐⣷⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠙⢷⣄⣀⡀⠀⢀⣴⠏⠀⠀
⠀⢠⣿⣽⣭⣿⠄⠀⠀⣀⡴⠿⢷⡀⠀⠘⡇⠀⠀⠀⠀⠀⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠀⠀⠀⠀⠈⠉⠉⠉⠀⠀⠀⠀
⣴⢟⣩⣤⡴⠦⣴⣶⠞⠉⠀⠀⠈⣧⠀⠀⢿⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠛⠿⠿⠋⠀⠀⠀⣿⠀⠀⠀⠀⠀⠈⠳⣤⣼⠆⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠘⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠸⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡟⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """
        return 64 if self.incl_len <= 60 else self.incl_len + 4
    
    def __post__init__(self):
        self.frame_number =  next(fnum)

    def parse(self) -> None:
        if self.frame:
            return self
        self.frame = identify_frame(self.data)
        return self
    
    def as_dict(self, frame_number: int = None) -> dict:
        res = {
            'frame_number': frame_number if frame_number != None else self.frame_number,
            'len_frame_pcap': self.incl_len,
            'len_frame_medium': self.medium_len,
            'frame_type': self.frame.frame_type.value,
            'src_mac': self.frame.source.mac,
            'dst_mac': self.frame.destination.mac
        }

        if isinstance(self.frame, IEEE_802_3_LLC_SNAP_Frame):
            res['pid'] = self.frame.ether_type.value
        
        if isinstance(self.frame, IEEE_802_3_LLC_Frame):
            res['sap'] = self.frame.DSAP.value
        
        if isinstance(self.frame, Ethernet2Frame):
            if self.frame.ether_type != EtherType.UNKNOWN:
                res['ether_type'] = self.frame.ether_type.value

            if self.frame.arp_opcode != None:
                res['arp_opcode'] = self.frame.arp_opcode

            if self.frame.source.ip:
                res['src_ip'] = self.frame.source.ip
            
            if self.frame.destination.ip:
                res['dst_ip'] = self.frame.destination.ip
            
            if self.frame.ip_id:
                res['id'] = self.frame.ip_id

            if self.frame.fragment_offset != -1:
                res['flags_mf'] = self.frame.more_fragments
                res['frag_offset'] = self.frame.fragment_offset
            
            if self.frame.communication_protocol:
                res['protocol'] = self.frame.communication_protocol.value
            
            if self.frame.icmp_type != None:
                res['icmp_type'] = self.frame.icmp_type
            
            if self.frame.source.port:
                res['src_port'] = self.frame.source.port
            
            if self.frame.destination.port:
                res['dst_port'] = self.frame.destination.port
            
            if self.frame.source.app and self.frame.source.app != TCPAppProtocol.UNKNOWN:
                res['app_protocol'] = self.frame.source.app.value
            
            elif self.frame.destination.app and self.frame.destination.app != TCPAppProtocol.UNKNOWN:
                res['app_protocol'] = self.frame.destination.app.value
        
        res['hexa_frame'] = self.beautiful_hexlify_data
        
        return res
