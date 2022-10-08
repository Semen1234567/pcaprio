import binascii


from pprint import pprint
from pcapreader import PCAPReader


# pcapfile = PCAPReader().read('./pcaps/trace-27.pcap')
pcapfile = PCAPReader().read('./pcaps/eth-1.pcap')



print(f'PCAP File Header: {pcapfile.header}')
with open('pcap.txt', 'w') as f:
    for p in pcapfile.packets[:]:
        PCAPReader().parse_packet(p)
        pprint(p, stream=f)
        # pprint(len(p.hexlify_data), stream=f)
        pprint(len(p.raw), stream=f)
        print(p.parsed_view.package_type)

    # pprint(p)
    # print(f'Packet data: {p.hexlify_data}')
    # print(f'Packet data: {p.hexlify_data}')
    # print(f'Packet data: {PCAPReader().parse_packet(p)}')