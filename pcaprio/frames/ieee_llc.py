from dataclasses import dataclass
from .ieee_llc_base import IEEE_802_3_LLC_BASE_Frame
from ..enumerations import FrameType


@dataclass
class IEEE_802_3_LLC_Frame(IEEE_802_3_LLC_BASE_Frame):
    frame_type: FrameType = FrameType.IEEE_802_3_LLC