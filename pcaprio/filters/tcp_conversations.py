from enum import Enum
from pprint import pprint
from typing import Callable, Generator, Iterable

from .iconversations import IConversations
from ..enumerations import CommunicationProtocol
from ..enumerations import EtherType
from ..enumerations import TCPFlag
from .base_filter import BaseFilter
from ..frames.ethernet2 import Ethernet2Frame
from ..pcap_packet import PCAPPacket



class TCP_COMPLETENESS:
    """TCP COMPLETENESS"""
    SYNSENT: int = 0x01  # TCP SYN SENT
    SYNACK:  int = 0x02  # TCP SYN ACK 
    ACK:     int = 0x04  # TCP ACK     
    DATA:    int = 0x08  # TCP data    
    FIN:     int = 0x10  # TCP FIN     
    RST:     int = 0x20  # TCP RST     


class TCPConversationsFilter(IConversations):
    def __init__(self, packets: Iterable[PCAPPacket], more_filters: Callable[[PCAPPacket], bool] = None):
        self._packets = BaseFilter(packets, [
            lambda x: isinstance(x.frame, Ethernet2Frame),
            lambda x: x.frame.ether_type == EtherType.IPv4,
            lambda x: x.frame.communication_protocol == CommunicationProtocol.TCP,
            *([more_filters] if more_filters else [])
        ]).filter()

        self._conversations: dict[str, list[PCAPPacket]] = {

        }

    @property
    def conversations(self) -> Iterable[list[PCAPPacket]]:
        return self._conversations.values()

    def detect_conversations(self) -> Iterable[list[PCAPPacket]]:
        for i, p in enumerate(self._packets, 1):
            p.frame_number = i

            frame = p.frame

            k1 = f"{frame.source.ip}:{frame.source.port}->{frame.destination.ip}:{frame.destination.port}"
            k2 = f"{frame.destination.ip}:{frame.destination.port}->{frame.source.ip}:{frame.source.port}"

            if k1 in self._conversations:
                self._conversations[k1].append(p)
            elif k2 in self._conversations:
                self._conversations[k2].append(p)
            else:
                self._conversations[k1] = [p]
        
        return self.conversations

    def get_conversation_completeness(self, conversation: list[PCAPPacket]) -> int:
        """
        Adapted From
        https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-tcp.c#L1502
                                                ======================
                                               < HA-HA... IT'S ME o_O >
                                                ======================
                                                      \     (`.
                                                       \     \ `.
                                                        \     )  `._..---._
                                            \`.       __...---`        o O )
                                             \ `._,--'           ,    ___,'
                                              ) ,-._          \  )   _,-'
                                             /,'    ``--.._____\/--''
        """
        conversation: list[Ethernet2Frame] = map(lambda x: x.frame, conversation)

        conversation_completeness: int = 0
        conversation_is_new: bool = True

        for frame in conversation:
            if conversation_is_new:
                if (frame.TCP_flag&(TCPFlag.SYN|TCPFlag.ACK)) == TCPFlag.SYN:
                    conversation_completeness |= TCP_COMPLETENESS.SYNSENT
                    if frame.seglen > 0:
                        conversation_completeness |= TCP_COMPLETENESS.DATA
                conversation_is_new = False
            else:
                # SYN-ACK
                if (frame.TCP_flag&(TCPFlag.SYN|TCPFlag.ACK)) == (TCPFlag.SYN|TCPFlag.ACK):
                    conversation_completeness |= TCP_COMPLETENESS.SYNACK
                
                # ACKs */
                if (frame.TCP_flag&(TCPFlag.SYN|TCPFlag.ACK)) == (TCPFlag.ACK):
                    if frame.seglen > 0: # transporting some data
                        conversation_completeness |= TCP_COMPLETENESS.DATA
                    else: #pure ACK
                        conversation_completeness |= TCP_COMPLETENESS.ACK
                
                # FIN-ACK
                if (frame.TCP_flag&(TCPFlag.FIN|TCPFlag.ACK)) == (TCPFlag.FIN|TCPFlag.ACK):
                    conversation_completeness |= TCP_COMPLETENESS.FIN
                
                # RST
                # XXX: A RST segment should be validated (RFC 9293 3.5.3),
                # and if not valid should not change the conversation state.
                # 
                if frame.TCP_flag&(TCPFlag.RST):
                    conversation_completeness |= TCP_COMPLETENESS.RST


        return conversation_completeness

    # 
    # display the TCP Conversation Completeness
    # we of course pay much attention on complete conversations but also incomplete ones which
    # have a regular start, as in practice we are often looking for such thing
    #
    @staticmethod
    def conversation_completeness_fill(value: int) -> str:
        return {
            TCP_COMPLETENESS.SYNSENT: ("INCOMPLETE", "SYN_SENT", value), 
            TCP_COMPLETENESS.SYNSENT|TCP_COMPLETENESS.SYNACK: ("INCOMPLETE", "CLIENT_ESTABLISHED", value), 
            TCP_COMPLETENESS.SYNSENT|TCP_COMPLETENESS.SYNACK|TCP_COMPLETENESS.ACK: ("INCOMPLETE", "ESTABLISHED", value), 
            TCP_COMPLETENESS.SYNSENT|TCP_COMPLETENESS.SYNACK|TCP_COMPLETENESS.ACK|TCP_COMPLETENESS.DATA: ("INCOMPLETE", "DATA", value), 
            TCP_COMPLETENESS.SYNSENT|TCP_COMPLETENESS.SYNACK|TCP_COMPLETENESS.ACK|TCP_COMPLETENESS.DATA|TCP_COMPLETENESS.FIN: ("COMPLETE", "WITH_DATA", value), 
            TCP_COMPLETENESS.SYNSENT|TCP_COMPLETENESS.SYNACK|TCP_COMPLETENESS.ACK|TCP_COMPLETENESS.DATA|TCP_COMPLETENESS.RST: ("COMPLETE", "WITH_DATA", value), 
            TCP_COMPLETENESS.SYNSENT|TCP_COMPLETENESS.SYNACK|TCP_COMPLETENESS.ACK|TCP_COMPLETENESS.DATA|TCP_COMPLETENESS.FIN|TCP_COMPLETENESS.RST: ("COMPLETE", "WITH_DATA", value), 
            TCP_COMPLETENESS.SYNSENT|TCP_COMPLETENESS.SYNACK|TCP_COMPLETENESS.ACK|TCP_COMPLETENESS.FIN: ("COMPLETE", "NO_DATA", value), 
            TCP_COMPLETENESS.SYNSENT|TCP_COMPLETENESS.SYNACK|TCP_COMPLETENESS.ACK|TCP_COMPLETENESS.RST: ("COMPLETE", "NO_DATA", value), 
            TCP_COMPLETENESS.SYNSENT|TCP_COMPLETENESS.SYNACK|TCP_COMPLETENESS.ACK|TCP_COMPLETENESS.FIN|TCP_COMPLETENESS.RST: ("COMPLETE", "NO_DATA", value)
        }.get(value, ("INCOMPLETE", "UNKNOWN", value))
    
    def sort_conversations(self) -> dict[str, list[PCAPPacket]]:
        s1 = dict(sorted(self._conversations.items(), key=lambda x: len(x[1]), reverse=True))

        for k in s1:
            s1[k] = sorted(s1[k], key=lambda x: x.frame_number)
        
        return s1
    
    def is_conversation_complete(self, conversation: list[PCAPPacket]) -> bool:
        return self.conversation_completeness_fill(self.get_conversation_completeness(conversation))[0] == "COMPLETE"