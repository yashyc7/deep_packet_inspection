from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.utils import PcapReader


class PcapReadError(Exception):
    """Raised when a PCAP file can't be read."""


@dataclass(frozen=True, slots=True)
class CapturedPacket:
    """Immutable capture record: timestamp plus serialized frame bytes."""

    timestamp: float
    raw_data: bytes


class PcapFileReader:
    """Stream packets from a PCAP file without loading the full capture."""

    def __init__(self, file_path: str | Path) -> None:
        self._file_path = Path(file_path)

        if not self._file_path.exists():
            raise FileNotFoundError(
                f"PCAP file doesn't exist on given path or path doesn't exist: {self._file_path}"
            )

        if not self._file_path.is_file():
            raise ValueError(f"Expected a file, but received: {self._file_path}")

    def __iter__(self) -> Iterator[CapturedPacket]:
        """Iterate over captured packets one frame at a time."""
        try:
            with PcapReader(str(self._file_path)) as pcap_reader:
                for packet in pcap_reader:
                    yield CapturedPacket(
                        timestamp=float(packet.time),
                        raw_data=bytes(packet),
                    )
        except (OSError, Scapy_Exception, EOFError, ValueError) as exc:
            raise PcapReadError(f"Failed to read the PCAP file {self._file_path}: {exc}") from exc
