import logging
import sys

from .pcap_file import PCAPFile
from .pcap_packet import PCAPPacket
from .pcap_header import PCAPFileHeader

from .frames.base import PCAPFrame
from .frames.ethernet2 import Ethernet2Frame
from .frames.ieee_llc import IEEE_802_3_LLC_Frame
from .frames.ieee_llc_snap import IEEE_802_3_LLC_SNAP_Frame


# PEP 585, Type Hinting Generics In Standard Collections
# https://www.python.org/dev/peps/pep-0585/
if sys.version_info < (3, 9):
    logging.error("Python 3.9 or higher is required")
    sys.exit(1)