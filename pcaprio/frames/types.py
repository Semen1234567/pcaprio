from dataclasses import dataclass

from ..enumerations import TCPAppProtocol
from ..enumerations import UDPAppProtocol


@dataclass
class EthernetSide:
    mac: str
    ip: str = None
    port: int = None
    app: TCPAppProtocol | UDPAppProtocol = None