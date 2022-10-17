

from typing import Generator, Iterable

from ..pcap_packet import PCAPPacket


class IConversations:
    def __init__(self, packets: Iterable[PCAPPacket]) -> None:
        raise NotImplementedError
    
    def detect_conversations(self) -> Generator[list[PCAPPacket], None, None]:
        raise NotImplementedError
    
    def is_conversation_complete(self, conversation: Iterable[PCAPPacket]) -> bool:
        raise NotImplementedError