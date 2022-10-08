import binascii

from dataclasses import dataclass, field

from enumerations import PackageType


class PCAPPacketParsedView:
    destination_mac: str
    source_mac: str
    
    package_type: PackageType = None

    def __init__(self, destination_mac: str, source_mac: str, package_type: PackageType = None) -> None:
        self.destination_mac = destination_mac
        self.source_mac = source_mac
        self.package_type = package_type
    
    def __repr__(self) -> str:
        return f'<PCAPPacketParsedView: {self.destination_mac} -> {self.source_mac} ({self.package_type})>'


@dataclass
class PCAPPacket:
    timestamp1: int
    timestamp2: int
    incl_len: int
    orig_len: int
    data: bytes

    raw: bytes = field(repr=False, default=None)
    parsed_view: PCAPPacketParsedView = field(default=None)

    @property
    def hexlify_data(self) -> str:
        return binascii.hexlify(self.data).decode('utf-8')

@dataclass
class PCAPFileHeader:
    magic_number: int = 0xa1b2c3d4
    version_major: int = 2
    version_minor: int = 4
    thiszone: int = 0
    sigfigs: int = 0
    snaplen: int = 65535
    link_type: int = 1

    raw: bytes = field(repr=False, default=None)


@dataclass
class PCAPFile:
    header: PCAPFileHeader = None
    packets: list[PCAPPacket] = field(default_factory=list)


@dataclass
class Ethernet2Frame(PCAPPacketParsedView):
    destination_mac: str
    source_mac: str
    ethertype: str
    data: bytes

    package_type: PackageType = PackageType.Ethernet2
    
    @property
    def hexlify_data(self) -> str:
        return binascii.hexlify(self.data).decode('utf-8')
