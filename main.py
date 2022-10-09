import os
import yaml


from pprint import pprint
from pcaprio.pcap_file import PCAPFile



for PCAP_NAME in os.listdir("pcaps"):
    PCAP_NAME = os.path.join("pcaps", PCAP_NAME)

    pcapfile = PCAPFile().read(PCAP_NAME)

    res = {
        "name": "PKS2022/23",
        "pcap_name": PCAP_NAME,
        "packets": [

        ]
    }


    for i, p in enumerate(pcapfile.read_packets(), 1):
        p.parse()
        res["packets"].append(p.as_dict(i))


    RES_NAME = PCAP_NAME.replace("pcap", "yaml")
    yaml.dump(res, open(RES_NAME, 'w'), sort_keys=False)
    print("Wrote", RES_NAME)

