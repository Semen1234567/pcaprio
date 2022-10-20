from ..enumerations import FrameType
from .types import EthernetSide


class PCAPFrame:
    destination: EthernetSide
    source: EthernetSide
    
    frame_type: FrameType = None
    isl: bytes = None


    def __init__(self, destination: EthernetSide, source: EthernetSide, frame_type: FrameType = None, isl: bytes = None, raw: bytes = None) -> None:
        self.destination = destination
        self.source = source
        self.frame_type = frame_type
        self.isl = isl
        self.raw = raw
    
    def __repr__(self) -> str:
        return f'<PCAPPacketParsedView: {self.destination} -> {self.source} ({self.frame_type.__repr__()})>'