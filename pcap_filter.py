import logging
import sys
import yaml


from pcaprio.enumerations import TCPAppProtocol, UDPAppProtocol
from pcaprio import PCAPFile

from pcaprio.filters import TCPConversationsFilter
from pcaprio.filters import TFTPConversationsFilter
from pcaprio.filters import ICMPConversationsFilter
from pcaprio.filters import ARPConversationsFilter


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
                # "src_comm": conversation[0].frame.source.ip,
                # "dst_comm": conversation[0].frame.destination.ip,
                "packets": [p.as_dict() for p in conversation]
            })
            partial_comms_id += 1
    
    if res["partial_comms"]:
        res["partial_comms"] = [res["partial_comms"][0]] # : (
    else:
        res.pop("partial_comms")
    
    if not res["complete_comms"]:
        res.pop("complete_comms")

    yaml.dump(res, open(output_file, 'w'), sort_keys=False)