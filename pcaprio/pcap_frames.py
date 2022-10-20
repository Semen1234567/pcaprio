from .enumerations import FrameType

from .frames.base import PCAPFrame
from .frames.types import EthernetSide
from .frames.ethernet2 import Ethernet2Frame
from .frames.ieee_llc import IEEE_802_3_LLC_Frame
from .frames.ieee_llc_snap import IEEE_802_3_LLC_SNAP_Frame


def identify_frame(raw_data: bytes) -> PCAPFrame:
    """
    Короче, это было на преднашке, страница 14 (преднашка 3_2022_Ethernet_linkova 20)
    """

    """Если первые 6 байт равны 01-00-0C-00-00, то это ISL. Его нужно вырезать. Я поп риколу добавляю новое поле isl. Вдруг понадобится...."""
    isl = None
    if raw_data.hex().startswith('01000c0000'):
        isl, raw_data = raw_data[:26], raw_data[26:]
    

    destination = EthernetSide(raw_data[0:6].hex(':').upper())
    source = EthernetSide(raw_data[6:12].hex(':').upper())

    if int.from_bytes(raw_data[12:14], 'big') >= 1500:
        return Ethernet2Frame(
            destination=destination,
            source=source,
            ether_type_code=raw_data[12:14].hex(),
            data=raw_data[14:],
            isl=isl,
            raw=raw_data
        )
    elif int.from_bytes(raw_data[12:14], 'big') < 1500:
        if raw_data[14:16].hex().upper() == "AAAA":
            return IEEE_802_3_LLC_SNAP_Frame(
                destination=destination,
                source=source,
                DSAP_code=raw_data[14:15].hex(),
                SSAP_code=raw_data[15:16].hex(),
                control=raw_data[16:17].hex(),
                vemdor_code=raw_data[17:20].hex(),
                ether_type_code=raw_data[20:22].hex(),
                data=raw_data[22:],
                isl=isl,
                raw=raw_data
            )
        elif raw_data[14:16].hex().upper() == "FFFF":
            return PCAPFrame(
                destination=destination,
                source=source,
                frame_type=FrameType.Novell_802_3_Raw,
                isl=isl,
                raw=raw_data
            )
        else:
            return IEEE_802_3_LLC_Frame(
                destination=destination,
                source=source,
                DSAP_code=raw_data[14:15].hex(),
                SSAP_code=raw_data[15:16].hex(),
                control=raw_data[16:17].hex(),
                data=raw_data[17:],
                isl=isl,
                raw=raw_data
            )