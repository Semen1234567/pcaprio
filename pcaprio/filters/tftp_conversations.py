from typing import Generator, Iterable

from pcaprio.filters.iconversations import IConversations
from ..enumerations import CommunicationProtocol, EtherType
from ..pcap_packet import PCAPPacket
from .base_filter import BaseFilter
from ..frames.ethernet2 import Ethernet2Frame



class TFTPConversationsFilter(IConversations):
    def __init__(self, packets: Iterable[PCAPPacket]):
        self._packets = BaseFilter(packets, [
                lambda x: isinstance(x.frame, Ethernet2Frame),
                lambda x: x.frame.ether_type == EtherType.IPv4,
                lambda x: x.frame.communication_protocol == CommunicationProtocol.UDP
            ]).filter_as_list()
    
    def detect_conversations(self) -> Generator[Generator[PCAPPacket, None, None], None, None]:
        conversations: list[PCAPPacket] = BaseFilter(self._packets, [
            lambda x: x.frame.destination.port == 69
        ]).filter()

        for p in conversations:
            yield BaseFilter(self._packets, [
                lambda x: x.frame.source.ip in [p.frame.source.ip, p.frame.destination.ip],
                lambda x: x.frame.destination.ip in [p.frame.source.ip, p.frame.destination.ip],
                lambda x: p.frame.source.port in [x.frame.source.port, x.frame.destination.port],
            ]).filter_as_list()
    
    def is_conversation_complete(self, conversation: Iterable[PCAPPacket]) -> bool:
        return True
