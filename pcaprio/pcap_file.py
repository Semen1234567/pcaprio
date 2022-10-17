import typing

from .pcap_header import PCAPFileHeader
from .pcap_packet import PCAPPacket
from .utils import number_gen
from io import IOBase


class PCAPFile:
    def __init__(self) -> None:
        self.data: bytes = b''
        self._raw: bytes = b''
        self.header: PCAPFileHeader = None
        self.packets: list[PCAPPacket] = []
        self.packet_num_gen = number_gen()
    
    def read(self, file: IOBase | str) -> 'PCAPFile':
        if isinstance(file, str):
            with open(file, 'rb') as f:
                self.data = f.read()
        else:
            self.data = file.read()
        
        self._raw = self.data[:]
        self._read_header()

        return self
    

    def read_packets(self) -> typing.Generator[PCAPPacket, None, None]:
        if not self.data:
            raise ValueError('No data to read')
        
        while True:
            packet = self._read_packet()
            if packet is None:
                break
            self.packets.append(packet)
            yield packet


    def _read_header(self) -> None:
        """
        From  https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html#name-file-header
        """

        header, self.data = self.data[:24], self.data[24:]
        self.header = PCAPFileHeader(
            int.from_bytes(header[:4], 'big'),
            int.from_bytes(header[4:6], 'little'),
            int.from_bytes(header[6:8], 'little'),
            int.from_bytes(header[8:12], 'little'),
            int.from_bytes(header[12:16], 'little'),
            int.from_bytes(header[16:20], 'little'),
            int.from_bytes(header[20:24], 'little'),
            header
        )
    
    def _read_packet(self) -> PCAPPacket | None:
        """
        From https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html#name-packet-record
        """

        packet, self.data = self.data[:16], self.data[16:]
        if not packet:
            return None
        timestamp1 = packet[0:4]
        timestamp2 = packet[4:8]
        incl_len = packet[8:12]
        orig_len = packet[12:16]
        frame_len = int.from_bytes(incl_len, 'little')
        data, self.data = self.data[:frame_len], self.data[frame_len:]


        return PCAPPacket(
            timestamp1=int.from_bytes(timestamp1, 'little'),
            timestamp2=int.from_bytes(timestamp2, 'little'),
            incl_len=int.from_bytes(incl_len, 'little'),
            orig_len=int.from_bytes(orig_len, 'little'),
            data=data,
            raw=packet + data,
            frame_number=next(self.packet_num_gen)
        )