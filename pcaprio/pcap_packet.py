import binascii



from dataclasses import dataclass
from dataclasses import field
from .frames_types import identify_frame
from .frames_types import PCAPFrame
from .enumerations import FrameType
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
            'dst_mac': self.frame.destination_mac,
            'hexa_frame': self.beautiful_hexlify_data
        }

        if self.frame.frame_type == FrameType.IEEE_802_3_LLC_SNAP:
            res['pid'] = self.frame.ether_type.value
        
        if self.frame.frame_type == FrameType.IEEE_802_3_LLC:
            res['sap'] = self.frame.DSAP.value
        
        return res
