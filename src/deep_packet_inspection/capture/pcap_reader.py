from dataclasses import dataclass
from pathlib import Path
from collections.abc import Iterator

from scapy.error import Scapy_Exception
from scapy.utils import PcapReader


class PcapReadError(Exception):
    """Raised when a PCAP file can't be read"""


@dataclass(frozen=True, slots=True)
class CapturedPacket:
    """Immutable presentation of the captured network packet
    the network packet consists of 6-7 information
    1. source ip
    2. source port
    3. destination ip
    4. destination port
    5. protocol : TCP/UDP/ etc etc
    6. SNI (ie domain name where we requested our data)
    7. data ( we genreally don't see into this)
    """

    timestamp: float
    raw_data: bytes


class PcapFileReader:
    """Reads packets from a PCAP file."""

    def __init__(self, file_path: str | Path) -> None:
        self._file_path = Path(file_path)

        # Agar file path nahi hai to FileNotFoundError raise karo
        if not self._file_path.exists():
            raise FileNotFoundError(
                f"PCAP file doesn't exist on given path or path doesn't exist: {self._file_path}"
            )

        if not self._file_path.is_file():
            raise ValueError(f"Expected a file, but received: {self._file_path}")

    def __iter__(self) -> Iterator[CapturedPacket]:
        """Iterate over captured packets."""
        try:
            with PcapReader(str(self._file_path)) as pcap_reader:
                for packet in pcap_reader:
                    yield CapturedPacket(
                        timestamp=float(packet.time),
                        raw_data=bytes(packet),
                    )
        except (OSError, Scapy_Exception, EOFError, ValueError) as exc:
            raise PcapReadError(
                f"Failed to read the PCAP file {self._file_path}: {exc}"
            ) from exc


"""
Why streaming?

Imagine a PCAP file containing 2 GB of network traffic.

Loading every packet into a Python list would consume substantial memory. Our iterator processes one packet at a time.

Also, frozen=True makes packet records immutable, preventing accidental modification after capture.

One limitation to keep in mind: this initial reader uses Scapy's decoded packet representation and serializes it back into bytes. It is appropriate for our first implementation, but we'll validate packet fidelity when building the output writer.
"""
