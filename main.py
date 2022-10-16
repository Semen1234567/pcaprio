import os
import yaml
import argparse

from pprint import pprint
from pcaprio.enumerations import TCPAppProtocol, EtherType
from pcaprio.pcap_frames import Ethernet2Frame
from pcaprio.pcap_file import PCAPFile



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


pcapfile = PCAPFile().read(input_file)

res = {
    "name": "PKS2022/23",
    "max_send_packets_by": [],
    "pcap_name": input_file,
    "packets": [

    ],
    "ipv4_senders": [],
}

ipv4_senders = {

}

for i, p in enumerate(pcapfile.read_packets(), 1):
    p.parse()

    if args.protocol:
        if not isinstance(p.frame, Ethernet2Frame):
            continue

        if p.frame.ether_type == EtherType.IPv4:
            app = p.frame.source_app if p.frame.source_app != TCPAppProtocol.UNKNOWN else p.frame.destination_app if p.frame.destination_app != TCPAppProtocol.UNKNOWN else None
            if not app or app.value != args.protocol:
                continue
        else:
            continue
    
    if isinstance(p.frame, Ethernet2Frame) and p.frame.ether_type == EtherType.IPv4:
        if p.frame.source_ip in ipv4_senders:
            ipv4_senders[p.frame.source_ip] += 1
        else:
            ipv4_senders[p.frame.source_ip] = 1

    res["packets"].append(p.as_dict(i))

ipv4_senders = [
    {"node": k, "number_of_sent_packets": v} for k, v in ipv4_senders.items()
]
ipv4_senders.sort(key=lambda x: x["number_of_sent_packets"], reverse=True)


res["max_send_packets_by"] = [
    element["node"] for element in filter(
        lambda x: x["number_of_sent_packets"] == ipv4_senders[0]["number_of_sent_packets"], ipv4_senders
    )
]
res["ipv4_senders"] = ipv4_senders

yaml.dump(res, open(output_file, 'w'), sort_keys=False)
print("Wrote", output_file)
