from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from deep_packet_inspection.engine.pipeline import DpiEngine
from deep_packet_inspection.engine.report import format_report
from deep_packet_inspection.flow.types import AppType
from deep_packet_inspection.rules.manager import RuleManager
from tests.helpers import build_dns_query, build_tls_client_hello


def _write_sample_pcap(path):
    tls = build_tls_client_hello("www.youtube.com")
    http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    dns = build_dns_query("www.google.com")

    packets = [
        Ether()
        / IP(src="192.168.1.100", dst="142.250.185.110")
        / TCP(sport=50000, dport=443)
        / Raw(tls),
        Ether()
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=50001, dport=80)
        / Raw(http),
        Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=53000, dport=53) / Raw(dns),
        Ether() / IP(src="192.168.1.50", dst="1.1.1.1") / TCP(sport=50002, dport=443) / Raw(b""),
    ]
    wrpcap(str(path), packets)
    return packets


def test_engine_classifies_and_reports(tmp_path):
    pcap = tmp_path / "sample.pcap"
    out = tmp_path / "out.pcap"
    _write_sample_pcap(pcap)

    engine = DpiEngine()
    stats = engine.process(pcap, out)

    assert stats.total_packets == 4
    assert stats.forwarded_packets == 4
    assert stats.dropped_packets == 0
    assert stats.flow_count == 4
    assert AppType.YOUTUBE in stats.app_counts
    assert AppType.DNS in stats.app_counts
    assert "www.youtube.com" in stats.detected_domains
    assert out.exists()
    assert out.stat().st_size > 0

    report = format_report(stats)
    assert "PROCESSING REPORT" in report
    assert "YouTube" in report


def test_engine_blocks_by_app_and_ip(tmp_path):
    pcap = tmp_path / "sample.pcap"
    out = tmp_path / "filtered.pcap"
    _write_sample_pcap(pcap)

    rules = RuleManager()
    rules.block_app("YouTube")
    rules.block_ip("192.168.1.50")

    engine = DpiEngine(rules=rules)
    stats = engine.process(pcap, out)

    assert stats.dropped_packets >= 2
    assert stats.forwarded_packets + stats.dropped_packets == stats.total_packets
    assert any("youtube" in event.lower() for event in engine.blocked_events)
