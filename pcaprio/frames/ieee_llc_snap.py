from dataclasses import dataclass
from dataclasses import field

from .ieee_llc_base import IEEE_802_3_LLC_BASE_Frame

from ..enumerations import FrameType
from ..enumerations import EtherTypes
from ..enumerations import EtherType


@dataclass
class IEEE_802_3_LLC_SNAP_Frame(IEEE_802_3_LLC_BASE_Frame):
    vemdor_code: str = field(default=None)

    frame_type: FrameType = FrameType.IEEE_802_3_LLC_SNAP
    ether_type: EtherType = field(default=None)
    ether_type_code: str = field(default=None)

    def __post_init__(self) -> None:
        super().__post_init__()

        self.ether_type_code = self.ether_type_code.upper()
        self.ether_type = EtherTypes.get(self.ether_type_code, EtherType.UNKNOWN)

