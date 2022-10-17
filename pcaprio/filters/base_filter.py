from typing import Callable, Generator, Iterable
from ..pcap_packet import PCAPPacket


FilterType = Callable[[PCAPPacket], bool]

class BaseFilter:
    def __init__(self, packets: Iterable[PCAPPacket], filters: list[FilterType] = None, log: bool = False):
        self._packets = packets

        if filters is None:
            self._filters: list[FilterType] = []
        else:
            self._filters = filters
        
        self._log = log
    
    def add_filter(self, filter: FilterType) -> None:
        self._filters.append(filter)
    
    def filter(self) -> Generator[PCAPPacket, None, None]:
        for packet in self._packets:
            if all(filter(packet.parse()) for filter in self._filters):
                yield packet
    
    def filter_as_list(self) -> list[PCAPPacket]:
        return list(self.filter())
    