import os

from pprint import pprint
from pcaprio.filters.tcp_conversations import TCPConversationsFilter
from pcaprio.filters.tftp_conversations import TFTPConversationsFilter
from pcaprio.filters.icmp_conversations import ICMPConversationsFilter
from pcaprio.filters.arp_conversations import ARPConversationsFilter
from pcaprio.pcap_file import PCAPFile



# for PCAP_NAME in os.listdir("pcaps"):
#     PCAP_NAME = os.path.join("pcaps", PCAP_NAME)
#     print(PCAP_NAME, file=open("output.txt", "a"))

#     pcapfile = PCAPFile().read(PCAP_NAME)


#     cf = TCPConversationsFilter(pcapfile.read_packets())

#     cf.distribute_by_tcp_conversation()
    
#     for k, v in cf.sort_conversations().items():
#         val = cf.get_conversation_completeness(v)
#         print(k, len(v), cf.conversation_completeness_fill(val), file=open("output.txt", "a"))
    
#     print(file=open("output.txt", "a"))







# open("output.txt", "w")

# for PCAP_NAME in os.listdir("pcaps"):
#     PCAP_NAME = os.path.join("pcaps", PCAP_NAME)
#     print(PCAP_NAME, file=open("output.txt", "a"))

#     pcapfile = PCAPFile().read(PCAP_NAME)


#     cf = TFTPConversationsFilter(pcapfile.read_packets())
    
#     for conversation in cf.detect_conversations():
#         print("---------------------"*10, file=open("output.txt", "a"))
#         for p in conversation:
#             print(p.frame, file=open("output.txt", "a"))
        
#         print("---------------------"*10, file=open("output.txt", "a"))
    
#     print(file=open("output.txt", "a"))









open("output.txt", "w")

for PCAP_NAME in os.listdir("pcaps"):
    PCAP_NAME = os.path.join("pcaps", PCAP_NAME)
    print(PCAP_NAME, file=open("output.txt", "a"))

    pcapfile = PCAPFile().read(PCAP_NAME)


    cf = ICMPConversationsFilter(pcapfile.read_packets())
    
    for conversation in cf.detect_conversations():
        print(cf.is_conversation_complete(conversation), "---------------------"*10, file=open("output.txt", "a"))
        for p in conversation:
            print(p.frame.icmp_type, "----", p.frame, file=open("output.txt", "a"))
        
        print("---------------------"*10, file=open("output.txt", "a"))
    
    print(file=open("output.txt", "a"))





# open("output.txt", "w")

# for PCAP_NAME in os.listdir("pcaps"):
#     PCAP_NAME = os.path.join("pcaps", PCAP_NAME)
#     print(PCAP_NAME, file=open("output.txt", "a"))

#     pcapfile = PCAPFile().read(PCAP_NAME)

#     cf = ARPConversationsFilter(pcapfile.read_packets())
    
#     for conversation in cf.detect_conversations():
#         print(cf.is_conversation_complete(conversation), "---------------------"*10, file=open("output.txt", "a"))
#         for p in conversation:
#             print(p.frame.arp_opcode, p.frame, file=open("output.txt", "a"))
        
#         print("---------------------"*10, file=open("output.txt", "a"))
    
#     print(file=open("output.txt", "a"))

