"""Write filtered packets to an output PCAP file."""

from __future__ import annotations

from pathlib import Path
from typing import Self

from scapy.utils import PcapWriter


class PcapFileWriter:
    """Append serialized Ethernet frames to a PCAP using Scapy."""

    def __init__(self, file_path: str | Path) -> None:
        self._file_path = Path(file_path)
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._writer = PcapWriter(str(self._file_path), append=False, sync=True)
        self._count = 0

    def write(self, raw_data: bytes) -> None:
        # PcapWriter expects a Packet-like object; bytes work via Raw/Ether rebuild.
        from scapy.layers.l2 import Ether

        self._writer.write(Ether(raw_data))
        self._count += 1

    @property
    def packet_count(self) -> int:
        return self._count

    @property
    def path(self) -> Path:
        return self._file_path

    def close(self) -> None:
        self._writer.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
