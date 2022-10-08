from binascii import unhexlify
from enumerations import EtherTypes
from pcap_structs import PCAPFile, PCAPPacket, PCAPFileHeader, Ethernet2Frame, PCAPPacketParsedView




class PCAPReader:
    def __init__(self) -> None:
        ...

    def read(self, filename: str) -> PCAPFile:
        pf = PCAPFile()

        with open(filename, 'rb') as f:
            pf.header = self.read_header(f)

            while (packet := self.read_packet(f)) is not None:
                pf.packets.append(packet)
        return pf
    
    def read_header(self, file) -> PCAPFileHeader:
        header = file.read(24)
        return PCAPFileHeader(
            int.from_bytes(header[:4], 'big'),
            int.from_bytes(header[4:6], 'little'),
            int.from_bytes(header[6:8], 'little'),
            int.from_bytes(header[8:12], 'little'),
            int.from_bytes(header[12:16], 'little'),
            int.from_bytes(header[16:20], 'little'),
            int.from_bytes(header[20:24], 'little'),
            header
        )
    
    def read_packet(self, file) -> PCAPPacket | None:
        """
        From https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html
        """
        packet = file.read(16)
        if not packet:
            return None
        timestamp1 = packet[0:4]
        timestamp2 = packet[4:8]
        incl_len = packet[8:12]
        orig_len = packet[12:16]
        data = file.read(int.from_bytes(incl_len, 'little'))

        return PCAPPacket(
            timestamp1=int.from_bytes(timestamp1, 'little'),
            timestamp2=int.from_bytes(timestamp2, 'little'),
            incl_len=int.from_bytes(incl_len, 'little'),
            orig_len=int.from_bytes(orig_len, 'little'),
            data=data,
            raw=packet + data
        )
    
    def parse_packet(self, packet: PCAPPacket) -> None:
        iseth = self.parse_packet_like_ethernet(packet)
        if iseth:
            packet.parsed_view = iseth
        
        else:
            packet.parsed_view = self.parse_packet_header_only(packet)
    
    def parse_packet_header_only(self, packet: PCAPPacket) -> None:
        destination_mac = packet.hexlify_data[0:12]
        source_mac = packet.hexlify_data[12:24]
        
        destination_mac = ':'.join(destination_mac[i:i+2] for i in range(0, len(destination_mac), 2))
        source_mac = ':'.join(source_mac[i:i+2] for i in range(0, len(source_mac), 2))

        return PCAPPacketParsedView(
            destination_mac=destination_mac,
            source_mac=source_mac
        )
    
    def parse_packet_like_ethernet(self, packet: PCAPPacket) -> Ethernet2Frame | None:
        destination_mac = packet.hexlify_data[0:12]
        source_mac = packet.hexlify_data[12:24]
        ethertype = packet.hexlify_data[24:28]

        if ethertype not in EtherTypes:
            return False
        
        ethertype_name = EtherTypes[ethertype]

        # data = unhexlify(packet.hexlify_data[28:])

        data = packet.data[14:]

        destination_mac = ':'.join(destination_mac[i:i+2] for i in range(0, len(destination_mac), 2))
        source_mac = ':'.join(source_mac[i:i+2] for i in range(0, len(source_mac), 2))
        
        return Ethernet2Frame(
            destination_mac=destination_mac,
            source_mac=source_mac,
            ethertype=ethertype_name,
            data=data
        )


    def __iter__(self):
        return iter(self.packats)