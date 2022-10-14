import binascii


from dataclasses import dataclass
from dataclasses import field
from .frames_types import Ethernet2Frame, IEEE_802_3_LLC_SNAP_Frame
from .frames_types import IEEE_802_3_LLC_Frame
from .frames_types import identify_frame
from .frames_types import PCAPFrame
from .enumerations import AppPort, EtherType, FrameType
from .utils import beautiful_hex



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


    def parse(self) -> None:
        self.frame = identify_frame(self.data)
    
    def as_dict(self, frame_number: int = None) -> dict:
        res = {
            'frame_number': frame_number if frame_number != None else -1,
            'len_frame_pcap': self.incl_len,
            'len_frame_medium': self.medium_len,
            'frame_type': self.frame.frame_type.value,
            'src_mac': self.frame.source_mac,
            'dst_mac': self.frame.destination_mac
        }

        if isinstance(self.frame, IEEE_802_3_LLC_SNAP_Frame):
            res['pid'] = self.frame.ether_type.value
        
        if isinstance(self.frame, IEEE_802_3_LLC_Frame):
            res['sap'] = self.frame.DSAP.value
        
        if isinstance(self.frame, Ethernet2Frame):
            if self.frame.ether_type != EtherType.UNKNOWN:
                res['ether_type'] = self.frame.ether_type.value
            
            if self.frame.source_ip:
                res['src_ip'] = self.frame.source_ip
            
            if self.frame.destination_ip:
                res['dst_ip'] = self.frame.destination_ip
            
            if self.frame.communication_protocol:
                res['protocol'] = self.frame.communication_protocol.value
            
            if self.frame.source_app_port:
                res['src_port'] = self.frame.source_app_port
            
            if self.frame.destination_app_port:
                res['dst_port'] = self.frame.destination_app_port
            
            if self.frame.source_app and self.frame.source_app != AppPort.UNKNOWN:
                res['app_protocol'] = self.frame.source_app.value
            elif self.frame.destination_app and self.frame.destination_app != AppPort.UNKNOWN:
                res['app_protocol'] = self.frame.destination_app.value
        
        res['hexa_frame'] = self.beautiful_hexlify_data
        
        return res
