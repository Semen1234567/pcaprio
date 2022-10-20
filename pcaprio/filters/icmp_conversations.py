from typing import Generator, Iterable

from .iconversations import IConversations
from .base_filter import BaseFilter
from ..enumerations import CommunicationProtocol, EtherType
from ..pcap_packet import PCAPPacket
from ..frames.ethernet2 import Ethernet2Frame



class ICMPConversationsFilter(IConversations):
    def __init__(self, packets: Iterable[PCAPPacket]):
        # Get all ICMP packets
        self._packets = BaseFilter(packets, [
                lambda x: isinstance(x.frame, Ethernet2Frame),
                lambda x: x.frame.ether_type == EtherType.IPv4,
                lambda x: x.frame.communication_protocol == CommunicationProtocol.ICMP
            ]).filter_as_list()
    
    def detect_conversations(self) -> Generator[list[PCAPPacket], None, None]:
        icmp_identifier_sequence_number_set = set()

        for p in self._packets:
            # If the packet is already in the set, skip it
            if (p.frame.icmp_identifier, p.frame.icmp_sequence_number) in icmp_identifier_sequence_number_set:
                continue
            
            # Add the packet to the set
            icmp_identifier_sequence_number_set.add((p.frame.icmp_identifier, p.frame.icmp_sequence_number) )

            # Get all packets with the same identifier and sequence number
            yield BaseFilter(self._packets, [
                lambda x: x.frame.icmp_sequence_number == p.frame.icmp_sequence_number and x.frame.icmp_identifier == p.frame.icmp_identifier
            ]).filter_as_list()
    
    def is_conversation_complete(self, conversation: Iterable[PCAPPacket]) -> bool:
        return any([p.frame.icmp_type == "Echo Reply" for p in conversation]) and any([p.frame.icmp_type == "Echo Request" for p in conversation])
