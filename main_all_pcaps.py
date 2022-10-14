import os
import yaml


from pprint import pprint
from pcaprio.enumerations import EtherType
from pcaprio.frames_types import Ethernet2Frame
from pcaprio.pcap_file import PCAPFile



for PCAP_NAME in os.listdir("pcaps"):
    PCAP_NAME = os.path.join("pcaps", PCAP_NAME)

    pcapfile = PCAPFile().read(PCAP_NAME)

    res = {
        "name": "PKS2022/23",
        "max_send_packets_by": [],
        "pcap_name": PCAP_NAME,
        "packets": [

        ],
        "ipv4_senders": [],
    }
    
    ipv4_senders = {

    }

    for i, p in enumerate(pcapfile.read_packets(), 1):
        p.parse()
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

    RES_NAME = PCAP_NAME.replace("pcap", "yaml")
    yaml.dump(res, open(RES_NAME, 'w'), sort_keys=False)
    print("Wrote", RES_NAME)
