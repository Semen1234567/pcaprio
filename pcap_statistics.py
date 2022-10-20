from typing import Callable
from pcaprio.enumerations import EtherType
from pcaprio import Ethernet2Frame
from pcaprio import PCAPFile


def collect_statistics(input_file: str, output_file: str, dumper: Callable):
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

    for p in pcapfile.read_packets():
        p.parse()
        if isinstance(p.frame, Ethernet2Frame) and p.frame.ether_type == EtherType.IPv4:
            if p.frame.source.ip in ipv4_senders:
                ipv4_senders[p.frame.source.ip] += 1
            else:
                ipv4_senders[p.frame.source.ip] = 1

        res["packets"].append(p.as_dict())
    
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

    dumper(res, open(output_file, 'w'), sort_keys=False)
