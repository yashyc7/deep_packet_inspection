"""Single-threaded DPI pipeline: read → parse → track → classify → filter → write."""

from __future__ import annotations

from pathlib import Path

from deep_packet_inspection.capture.pcap_reader import CapturedPacket, PcapFileReader
from deep_packet_inspection.capture.pcap_writer import PcapFileWriter
from deep_packet_inspection.flow.tracker import FlowTracker
from deep_packet_inspection.flow.types import ProcessingStats
from deep_packet_inspection.inspection.classify import classify_flow
from deep_packet_inspection.parser.packet_parser import PacketParser
from deep_packet_inspection.rules.manager import RuleManager


class DpiEngine:
    """Offline deep packet inspection engine."""

    def __init__(self, rules: RuleManager | None = None) -> None:
        self.rules = rules or RuleManager()
        self.parser = PacketParser()
        self.tracker = FlowTracker()
        self.stats = ProcessingStats()
        self._blocked_events: list[str] = []

    @property
    def blocked_events(self) -> list[str]:
        return list(self._blocked_events)

    def process(
        self,
        input_path: str | Path,
        output_path: str | Path | None = None,
    ) -> ProcessingStats:
        """Process an input PCAP and optionally write a filtered output PCAP."""

        self.tracker = FlowTracker()
        self.stats = ProcessingStats()
        self._blocked_events.clear()

        writer: PcapFileWriter | None = None
        try:
            if output_path is not None:
                writer = PcapFileWriter(output_path)

            for captured in PcapFileReader(input_path):
                self._process_packet(captured, writer)
        finally:
            if writer is not None:
                writer.close()

        self.stats.flow_count = len(self.tracker)
        for flow in self.tracker.flows():
            if flow.sni:
                self.stats.detected_domains[flow.sni] = flow.app_type

        return self.stats

    def _process_packet(
        self,
        captured: CapturedPacket,
        writer: PcapFileWriter | None,
    ) -> None:
        self.stats.total_packets += 1
        packet = self.parser.parse(captured.timestamp, captured.raw_data)

        if packet.protocol == "TCP":
            self.stats.tcp_packets += 1
        elif packet.protocol == "UDP":
            self.stats.udp_packets += 1
        else:
            self.stats.other_packets += 1

        flow = self.tracker.update(packet, frame_size=len(captured.raw_data))

        # Non-IP or non-TCP/UDP packets are forwarded (not classifiable as flows).
        if flow is None:
            self.stats.forwarded_packets += 1
            if writer is not None:
                writer.write(captured.raw_data)
            return

        classify_flow(flow, packet)

        if not flow.blocked and self.rules.is_blocked(packet.src_ip, flow.app_type, flow.sni):
            flow.blocked = True
            label = flow.app_type.name
            detail = f"{packet.src_ip} -> {packet.dst_ip} ({label}"
            if flow.sni:
                detail += f": {flow.sni}"
            detail += ")"
            self._blocked_events.append(detail)

        self.stats.app_counts[flow.app_type] = self.stats.app_counts.get(flow.app_type, 0) + 1

        if flow.blocked:
            self.stats.dropped_packets += 1
            return

        self.stats.forwarded_packets += 1
        if writer is not None:
            writer.write(captured.raw_data)
