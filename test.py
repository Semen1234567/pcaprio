import os

from pprint import pprint
from filters.communications import TCPCommunicationsFilter
from pcaprio.pcap_file import PCAPFile




for PCAP_NAME in os.listdir("pcaps"):
    PCAP_NAME = os.path.join("pcaps", PCAP_NAME)
    print(PCAP_NAME, file=open("output.txt", "a"))

    pcapfile = PCAPFile().read(PCAP_NAME)


    cf = TCPCommunicationsFilter(pcapfile.read_packets())

    cf.distribute_by_tcp_communications()

    for i in cf.sort_communications():
        val = cf.get_conversation_completeness(cf.communications[i])
        print(i, len(cf.communications[i]), cf.conversation_completeness_fill(val), file=open("output.txt", "a"))
    
    print(file=open("output.txt", "a"))