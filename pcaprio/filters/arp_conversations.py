from typing import Generator, Iterable
from ..enumerations import ARPOpcode, EtherType
from ..pcap_frames import Ethernet2Frame
from ..pcap_packet import PCAPPacket
from .base_filter import BaseFilter



class ARPConversationsFilter:
    def __init__(self, packets: Iterable[PCAPPacket]):
        self._packets = BaseFilter(packets, [
                lambda x: isinstance(x.frame, Ethernet2Frame),
                lambda x: x.frame.ether_type == EtherType.ARP,
            ]).filter_as_list()

    def detect_arp_conversations(self) -> Generator[tuple[list[PCAPPacket], bool], None, None]:
        arp_conv_set = set()

        for p in self._packets:
            if (p.frame.source.ip, p.frame.destination.ip) in arp_conv_set or (p.frame.destination.ip, p.frame.source.ip) in arp_conv_set:
                continue

            arp_conv_set.add((p.frame.source.ip, p.frame.destination.ip))
            conv = BaseFilter(self._packets, [
                lambda x: x.frame.source.ip in [p.frame.source.ip, p.frame.destination.ip],
                lambda x: x.frame.destination.ip in [p.frame.source.ip, p.frame.destination.ip],
            ]).filter_as_list()

            yield conv, self.is_conversation_complete(conv)

    def is_conversation_complete(self, conversation: Iterable[PCAPPacket]) -> bool:
        return any([p.frame.arp_opcode == ARPOpcode.Reply for p in conversation]) and any([p.frame.arp_opcode == ARPOpcode.Request for p in conversation])

