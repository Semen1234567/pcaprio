import logging
import sys
import yaml


from pcaprio.enumerations import TCPAppProtocol, EtherType, UDPAppProtocol
from pcaprio.filters.iconversations import IConversations
from pcaprio.pcap_frames import Ethernet2Frame
from pcaprio.pcap_file import PCAPFile

from pcaprio.filters.tcp_conversations import TCPConversationsFilter
from pcaprio.filters.tftp_conversations import TFTPConversationsFilter
from pcaprio.filters.icmp_conversations import ICMPConversationsFilter
from pcaprio.filters.arp_conversations import ARPConversationsFilter


logger = logging.getLogger("pcaprio")

def collect_data_by_protocol(protocol: str | None, input_file: str, output_file: str):
    if not any((
        TCPAppProtocol(protocol) != TCPAppProtocol.UNKNOWN, protocol == "TCP", 
        UDPAppProtocol(protocol) != UDPAppProtocol.UNKNOWN,
        protocol == "ICMP",
        protocol == "ARP"
    )):
        logger.error("Protocol not supported")
        exit(1)
    
    res = {
        "name": "PKS2022/23",
        "pcap_name": input_file,
        "filter_name": protocol,
        "complete_comms": [],
        "partial_comms": [],
    }

    pcapfile = PCAPFile().read(input_file)

    if protocol == "TCP":
        cf = TCPConversationsFilter(pcapfile.read_packets())
    if TCPAppProtocol(protocol) != TCPAppProtocol.UNKNOWN:
        cf = TCPConversationsFilter(pcapfile.read_packets(), lambda x: x.frame.source.app == TCPAppProtocol(protocol) or x.frame.destination.app == TCPAppProtocol(protocol))
    if UDPAppProtocol(protocol) != UDPAppProtocol.UNKNOWN:
        cf = TFTPConversationsFilter(pcapfile.read_packets())
    if protocol == "ICMP":
        cf = ICMPConversationsFilter(pcapfile.read_packets())
    if protocol == "ARP":
        cf = ARPConversationsFilter(pcapfile.read_packets())

    complete_comms_id = 1
    partial_comms_id = 1
    
    for conversation in cf.detect_conversations():
        is_complete = cf.is_conversation_complete(conversation)
        if is_complete:
            res["complete_comms"].append({
                "number_comm": complete_comms_id,
                "src_comm": conversation[0].frame.source.ip,
                "dst_comm": conversation[0].frame.destination.ip,
                "packets": [p.as_dict() for p in conversation]
            })
            complete_comms_id += 1
        else:
            res["partial_comms"].append({
                "number_comm": partial_comms_id,
                "src_comm": conversation[0].frame.source.ip,
                "dst_comm": conversation[0].frame.destination.ip,
                "packets": [p.as_dict() for p in conversation]
            })
            partial_comms_id += 1
    if res["partial_comms"]:
        res["partial_comms"] = res["partial_comms"][0] # :

    yaml.dump(res, open(output_file, 'w'), sort_keys=False)
    print("Wrote", output_file)