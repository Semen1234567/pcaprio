import logging
import os
import time
import argparse
import sys

from typing import Generator
from dumper import get_dumper
from pcap_filter import collect_data_by_protocol
from pcap_statistics import collect_statistics
from emoj import kekw


class ColoredLogger(logging.Logger):
    def __init__(self, name, level=logging.INFO):
        super().__init__(name, level)

    def _log(self, level, msg, args, exc_info=None, extra=None, stack_info=False):
        if level == logging.ERROR:
            msg = f"\033[91m{msg}\033[0m"
        elif level == logging.WARNING:
            msg = f"\033[93m{msg}\033[0m"
        elif level == logging.INFO:
            msg = f"\033[92m{msg}\033[0m"
        super()._log(level, msg, args, exc_info, extra, stack_info)

def ticker_string(string: str) -> Generator[str, None, None]:
    string = " "*50 + string + " "*5
    while string:
        yield string[:50]
        string = string[1:]


def my_except_hook(exctype, value, traceback):
    if exctype == KeyboardInterrupt: print(kekw); sys.exit(0)
    else: sys.__excepthook__(exctype, value, traceback)
sys.excepthook = my_except_hook


logger = ColoredLogger("pcaprio")
logger.setLevel(logging.INFO)



logo = """
██▓███   ▄████▄   ▄▄▄       ██▓███   ██▀███   ██▓ ▒█████  
▓██░  ██▒▒██▀ ▀█  ▒████▄    ▓██░  ██▒▓██ ▒ ██▒▓██▒▒██▒  ██▒
▓██░ ██▓▒▒▓█    ▄ ▒██  ▀█▄  ▓██░ ██▓▒▓██ ░▄█ ▒▒██▒▒██░  ██▒
▒██▄█▓▒ ▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▒██▄█▓▒ ▒▒██▀▀█▄  ░██░▒██   ██░
▒██▒ ░  ░▒ ▓███▀ ░ ▓█   ▓██▒▒██▒ ░  ░░██▓ ▒██▒░██░░ ████▓▒░
▒▓▒░ ░  ░░ ░▒ ▒  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░░ ▒▓ ░▒▓░░▓  ░ ▒░▒░▒░ 
░▒ ░       ░  ▒     ▒   ▒▒ ░░▒ ░       ░▒ ░ ▒░ ▒ ░  ░ ▒ ▒░ 
░░       ░          ░   ▒   ░░         ░░   ░  ▒ ░░ ░ ░ ▒  
         ░ ░            ░  ░            ░      ░      ░ ░  
         ░                                                
                    PCAP FILE ANALYZER
"""


parser = argparse.ArgumentParser()
parser.print_help_old = parser.print_help
parser.print_help = lambda : (print(logo), parser.print_help_old())

parser.add_argument(
    "--заповiт", help="На щасття........", action="store_true"
)

parser.add_argument(
    '-p', '--protocol', help="Filter by protocol", type=str, default=None
)

parser.add_argument(
    '-i', '--input', help=".pcap file to parse", type=str, default=None, required=True
)

parser.add_argument(
    '-o', '--output', help="Output file", type=str, default=None
)

parser.add_argument(
    '--output-format', help="Output format", type=str, default="yaml"
)

parser.add_argument(
    '--partial-comms-limit', help="partial_comms limit", type=int, default=1
)

args = parser.parse_args()

if args.заповiт:
    for i in ticker_string("Як умру, то поховайте Мене на могилі Серед степу широкого На Вкраїні милій, Щоб лани широкополі, І Дніпро, і кручі Було видно, було чути, Як реве ревучий. Як понесе з України У синєє море Кров ворожу... отойді я І лани і гори — Все покину, і полину До самого Бога Молитися... а до того Я не знаю Бога. Поховайте та вставайте, Кайдани порвіте І вражою злою кров’ю Волю окропіте. І мене в сем’ї великій, В сем’ї вольній, новій, Не забудьте пом’янути Незлим тихим словом."):
        print(i, end="\r")
        time.sleep(0.1)

partial_comms_limit = args.partial_comms_limit

try:
    dumper = get_dumper(args.output_format)
    output_format = args.output_format
except ValueError:
    logger.error(f"Unknown output format {args.output_format}")
    sys.exit(1)


input_files = []
output_files = []

if os.path.isdir(args.input):
    input_files = [os.path.abspath(os.path.join(args.input, f)) for f in os.listdir(args.input)]
elif os.path.exists(args.input):
    input_files = [os.path.abspath(args.input), ]
else:
    logger.error(f"{args.input} not found")
    exit(1)


if not args.output:
    for f in input_files:
        output_files.append(f"{f}.{output_format}")
elif os.path.isdir(args.output):
    output_files = [os.path.abspath(os.path.join(args.output, f"{f}.{output_format}")) for f in os.listdir(args.input)]
elif len(input_files) == 1:
    output_files = [os.path.abspath(args.output), ]
else:
    for f in input_files:
        output_files.append(f"{f}.{output_format}")



for input_file, output_file in zip(input_files, output_files):
    t1 = time.time()
    if args.protocol:
        protocol = args.protocol.upper()
        collect_data_by_protocol(protocol, input_file, output_file, dumper, partial_comms_limit)
    else:
        collect_statistics(input_file, output_file, dumper)
    t2 = time.time()

    print("-"*10)
    print(f"Wrote {output_file}")
    print(f"Time: {t2 - t1:.2f}s")
    print("-"*10)
