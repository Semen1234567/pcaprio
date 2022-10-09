import binascii

from dataclasses import dataclass
from dataclasses import field
from .enumerations import FrameType
from .enumerations import EtherTypes
from .enumerations import EtherType
from .enumerations import IEEE_SAPs
from .enumerations import IEEE_SAP



class PCAPFrame:
    destination_mac: str
    source_mac: str
    
    frame_type: FrameType = None
    isl: bytes = None

    def __init__(self, destination_mac: str, source_mac: str, frame_type: FrameType = None, isl: bytes = None) -> None:
        self.destination_mac = destination_mac
        self.source_mac = source_mac
        self.frame_type = frame_type
        self.isl = isl
    
    def __repr__(self) -> str:
        return f'<PCAPPacketParsedView: {self.destination_mac} -> {self.source_mac} ({self.frame_type.__repr__()})>'


@dataclass
class Ethernet2Frame(PCAPFrame):
    destination_mac: str
    source_mac: str
    data: bytes
    ether_type: str = field(default=None)
    isl: bytes = field(repr=False, default=None)


    ether_type_code: str = field(repr=False, default=None)
    frame_type: FrameType = FrameType.Ethernet2

    def __post_init__(self) -> None:
        self.ether_type_code = self.ether_type_code.upper()
        self.ether_type = EtherTypes.get(self.ether_type_code, EtherType.UNKNOWN)
    
    @property
    def hexlify_data(self) -> str:
        return binascii.hexlify(self.data).decode('utf-8').upper()


@dataclass
class IEEE_802_3_LLC_BASE_Frame(PCAPFrame):
    destination_mac: str
    source_mac: str
    data: bytes
    DSAP: IEEE_SAP = field(default=None)
    SSAP: IEEE_SAP = field(default=None)
    control: str = field(default=None)
    isl: bytes = field(repr=False, default=None)

    DSAP_code: str = field(repr=False, default=None)
    SSAP_code: str = field(repr=False, default=None)

    def __post_init__(self) -> None:
        self.control = self.control.upper()
        self.DSAP_code = self.DSAP_code.upper()
        self.SSAP_code = self.SSAP_code.upper()
        self.DSAP = IEEE_SAPs.get(self.DSAP_code, IEEE_SAP.UNKNOWN)
        self.SSAP = IEEE_SAPs.get(self.SSAP_code, IEEE_SAP.UNKNOWN)

    @property
    def hexlify_data(self) -> str:
        return binascii.hexlify(self.data).decode('utf-8').upper()


@dataclass
class IEEE_802_3_LLC_Frame(IEEE_802_3_LLC_BASE_Frame):
    frame_type: FrameType = FrameType.IEEE_802_3_LLC


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




def identify_frame(raw_data: bytes) -> PCAPFrame:
    """
    Короче, это было на преднашке, страница 14 (преднашка 3_2022_Ethernet_linkova 20)
    """

    """Если первые 6 байт равны 01-00-0C-00-00, то это ISL. Его нужно вырезать. Я поп риколу добавляю новое поле isl. Вдруг понадобится...."""
    isl = None
    if raw_data.hex().startswith('01000c0000'):
        isl, raw_data = raw_data[:26], raw_data[26:]
    

    destination_mac = raw_data[0:6].hex(':').upper()
    source_mac = raw_data[6:12].hex(':').upper()

    if int.from_bytes(raw_data[12:14], 'big') >= 1500:
        return Ethernet2Frame(
            destination_mac=destination_mac,
            source_mac=source_mac,
            ether_type_code=raw_data[12:14].hex(),
            data=raw_data[14:],
            isl=isl
        )
    elif int.from_bytes(raw_data[12:14], 'big') < 1500:
        if raw_data[14:16].hex().upper() == "AAAA":
            return IEEE_802_3_LLC_SNAP_Frame(
                destination_mac=destination_mac,
                source_mac=source_mac,
                DSAP_code=raw_data[14:15].hex(),
                SSAP_code=raw_data[15:16].hex(),
                control=raw_data[16:17].hex(),
                vemdor_code=raw_data[17:20].hex(),
                ether_type_code=raw_data[20:22].hex(),
                data=raw_data[22:],
                isl=isl
            )
        elif raw_data[14:16].hex().upper() == "FFFF":
            return PCAPFrame(
                destination_mac=destination_mac,
                source_mac=source_mac,
                frame_type=FrameType.Novell_802_3_Raw,
                isl=isl
            )
        else:
            return IEEE_802_3_LLC_Frame(
                destination_mac=destination_mac,
                source_mac=source_mac,
                DSAP_code=raw_data[14:15].hex(),
                SSAP_code=raw_data[15:16].hex(),
                control=raw_data[16:17].hex(),
                data=raw_data[17:],
                isl=isl
            )