import os
from typing import Generator
import yaml
import argparse

from pprint import pprint
from pcaprio.enumerations import TCPAppProtocol, EtherType, UDPAppProtocol
from pcaprio.pcap_frames import Ethernet2Frame
from pcaprio.pcap_file import PCAPFile

from pcaprio.filters.tcp_conversations import TCPConversationsFilter
from pcaprio.filters.tftp_conversations import TFTPConversationsFilter
from pcaprio.filters.icmp_conversations import ICMPConversationsFilter
from pcaprio.filters.arp_conversations import ARPConversationsFilter



parser = argparse.ArgumentParser(description='PKS WTF')
parser.add_argument(
    '-p', '--protocol', help="Filter by protocol", type=str, default=None
)

parser.add_argument(
    '-i', '--input', help=".pcap file to parse", type=str, default=None, required=True
)

parser.add_argument(
    '-o', '--output', help="Output file", type=str, default=None, required=True
)


args = parser.parse_args()

input_file = os.path.abspath(args.input)
output_file = os.path.abspath(args.output)
if args.protocol:
    protocol = args.protocol.upper()
else:
    protocol = None


pcapfile = PCAPFile().read(input_file)

res = {
    "name": "PKS2022/23",
    "max_send_packets_by": [],
    "pcap_name": input_file,
}

if (TCPAppProtocol(protocol) != TCPAppProtocol.UNKNOWN or protocol == "TCP" or 
    UDPAppProtocol(protocol) != UDPAppProtocol.UNKNOWN or
    protocol == "ICMP" or
    protocol == "ARP" 
    ):
    res["complete_comms"] = []
    res["partial_comms"] = []


if TCPAppProtocol(protocol) != TCPAppProtocol.UNKNOWN or protocol == "TCP":
    if protocol != "TCP":
        cf = TCPConversationsFilter(pcapfile.read_packets(), lambda x: x.frame.source.app == TCPAppProtocol(protocol) or x.frame.destination.app == TCPAppProtocol(protocol))
    else:
        cf = TCPConversationsFilter(pcapfile.read_packets())

    cf.distribute_by_tcp_conversation()
    complete_comms_id = 1
    partial_comms_id = 1

    for k, v in cf.sort_conversations().items():
        conv_sides = [s.split(':')[0] for s in k.split("->")]
        val = cf.get_conversation_completeness(v)
        is_complete = cf.conversation_completeness_fill(val)
        if is_complete[0] == "COMPLETE":
            res["complete_comms"].append({
                "number_comm": complete_comms_id,
                "src_comm": conv_sides[0],
                "dst_comm": conv_sides[1],
                "packets": [p.as_dict() for p in v]
            })
            complete_comms_id += 1
        else:
            res["partial_comms"].append({
                "number_comm": partial_comms_id,
                "packets": [p.as_dict() for p in v]
            })
            partial_comms_id += 1


if UDPAppProtocol(protocol) != UDPAppProtocol.UNKNOWN:
    cf = TFTPConversationsFilter(pcapfile.read_packets())
    complete_comms_id = 1
    
    for conversation in cf.detect_tftp_conversations():
        for p in conversation:
            res["complete_comms"].append({
                "number_comm": complete_comms_id,
                "src_comm": v[0].frame.source.ip,
                "dst_comm": v[0].frame.destination.ip,
                "packets": [p.as_dict() for p in v]
            })
            complete_comms_id += 1
        

if protocol == "ICMP":
    cf = ICMPConversationsFilter(pcapfile.read_packets())
    
    complete_comms_id = 1
    partial_comms_id = 1
    

    for conversation in cf.detect_icmp_conversations():
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
                "packets": [p.as_dict() for p in conversation]
            })
            partial_comms_id += 1


if protocol == "ARP":
    cf = ARPConversationsFilter(pcapfile.read_packets())
        
    complete_comms_id = 1
    partial_comms_id = 1
    
    for conversation, is_complet in cf.detect_arp_conversations():
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
                "packets": [p.as_dict() for p in conversation]
            })
            partial_comms_id += 1


yaml.dump(res, open(output_file, 'w'), sort_keys=False)
print("Wrote", output_file)
