from dataclasses import dataclass, field




@dataclass(frozen=True)
class PCAPFileHeader:
    magic_number: int = 0xa1b2c3d4
    version_major: int = 2
    version_minor: int = 4
    thiszone: int = 0
    sigfigs: int = 0
    snaplen: int = 65535
    link_type: int = 1

    raw: bytes = field(repr=False, default=None)