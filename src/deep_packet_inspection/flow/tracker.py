"""Bidirectional-aware unidirectional flow table keyed by five-tuple."""

from __future__ import annotations

from deep_packet_inspection.flow.types import FiveTuple, Flow
from deep_packet_inspection.parser.packet_parser import ParsedPacket


class FlowTracker:
    """Track per-flow packet/byte counts and classification state."""

    def __init__(self) -> None:
        self._flows: dict[FiveTuple, Flow] = {}

    def update(self, packet: ParsedPacket, frame_size: int) -> Flow | None:
        """Update or create a flow for a parsed IP/TCP|UDP packet.

        Returns None when the packet cannot form a five-tuple (e.g. ARP).
        """

        if packet.src_ip is None or packet.dst_ip is None:
            return None
        if packet.src_port is None or packet.dst_port is None:
            return None
        if packet.protocol not in {"TCP", "UDP"}:
            return None

        key = FiveTuple(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )

        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(key=key, first_seen=packet.timestamp)
            self._flows[key] = flow

        flow.packet_count += 1
        flow.byte_count += frame_size
        flow.last_seen = packet.timestamp
        return flow

    def get(self, key: FiveTuple) -> Flow | None:
        return self._flows.get(key)

    def flows(self) -> list[Flow]:
        return list(self._flows.values())

    def __len__(self) -> int:
        return len(self._flows)
