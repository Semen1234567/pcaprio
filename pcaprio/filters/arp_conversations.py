from typing import Generator, Iterable

from .iconversations import IConversations
from ..enumerations import ARPOpcode, EtherType
from ..pcap_frames import Ethernet2Frame
from ..pcap_packet import PCAPPacket
from .base_filter import BaseFilter

def divide_one_by_many(conversation: Iterable[PCAPPacket]) -> Generator[PCAPPacket, None, None]:
    """Divide one conversation into many conversations."""
    stack = []
    for packet in conversation:
        if packet.frame.arp_opcode == ARPOpcode.REQUEST:
            stack.append(packet)
        elif packet.frame.arp_opcode == ARPOpcode.REPLY:
            stack.append(packet)
            yield stack
            stack = []


class ARPConversationsFilter(IConversations):
    def __init__(self, packets: Iterable[PCAPPacket]):
        self._packets = BaseFilter(packets, [
                lambda x: isinstance(x.frame, Ethernet2Frame),
                lambda x: x.frame.ether_type == EtherType.ARP,
            ]).filter_as_list()

    def detect_conversations(self) -> Generator[list[PCAPPacket], None, None]:
        arp_conv_set = set()

        for p in self._packets:
            if (p.frame.source.ip, p.frame.destination.ip) in arp_conv_set or (p.frame.destination.ip, p.frame.source.ip) in arp_conv_set:
                continue

            arp_conv_set.add((p.frame.source.ip, p.frame.destination.ip))
            conv = BaseFilter(self._packets, [
                lambda x: x.frame.source.ip in [p.frame.source.ip, p.frame.destination.ip],
                lambda x: x.frame.destination.ip in [p.frame.source.ip, p.frame.destination.ip],
            ]).filter_as_list()
            for c in divide_one_by_many(conv):
                yield c

    def is_conversation_complete(self, conversation: Iterable[PCAPPacket]) -> bool:
        return any([p.frame.arp_opcode == ARPOpcode.REPLY for p in conversation]) and any([p.frame.arp_opcode == ARPOpcode.REQUEST for p in conversation])

