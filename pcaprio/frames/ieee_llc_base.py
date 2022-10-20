import binascii

from dataclasses import dataclass
from dataclasses import field

from .base import PCAPFrame
from .types import EthernetSide

from ..enumerations import IEEE_SAPs
from ..enumerations import IEEE_SAP


@dataclass
class IEEE_802_3_LLC_BASE_Frame(PCAPFrame):
    destination: EthernetSide
    source: EthernetSide
    data: bytes
    DSAP: IEEE_SAP = field(default=None)
    SSAP: IEEE_SAP = field(default=None)
    control: str = field(default=None)
    isl: bytes = field(repr=False, default=None)

    DSAP_code: str = field(repr=False, default=None)
    SSAP_code: str = field(repr=False, default=None)
    raw: bytes = field(repr=False, default=None)

    def __post_init__(self) -> None:
        self.control = self.control.upper()
        self.DSAP_code = self.DSAP_code.upper()
        self.SSAP_code = self.SSAP_code.upper()
        self.DSAP = IEEE_SAPs.get(self.DSAP_code, IEEE_SAP.UNKNOWN)
        self.SSAP = IEEE_SAPs.get(self.SSAP_code, IEEE_SAP.UNKNOWN)

    @property
    def hexlify_data(self) -> str:
        return binascii.hexlify(self.data).decode('utf-8').upper()