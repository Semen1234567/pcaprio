from pprint import pprint
from pcaprio.pcap_file import PCAPFile


# pcapfile = PCAPFile().read('./pcaps/eth-1.pcap')
pcapfile = PCAPFile().read('./pcaps/trace-27.pcap')
print(f'PCAP File Header: {pcapfile.header}')


f = open('output.txt', 'w')
for i, p in enumerate(pcapfile.read_packets()):
    p.parse()

    print(f'Packet {i}:', file=f)
    pprint(p, stream=f)

f.close()