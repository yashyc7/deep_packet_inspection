import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from deep_packet_inspection.capture.pcap_reader import (
    CapturedPacket,
    PcapFileReader,
    PcapReadError,
)


def test_read_packets_from_pcap(tmp_path):
    pcap_path = tmp_path / "test.pcap"

    original_packets = [
        Ether() / IP(dst="8.8.8.8") / UDP(dport=53) / Raw(b"DNS"),
        Ether() / IP(dst="1.1.1.1") / UDP(dport=53) / Raw(b"QUERY"),
    ]
    wrpcap(
        str(pcap_path), original_packets
    )  # making packets file so that we can test our reader functionality here
    reader = PcapFileReader(file_path=pcap_path)
    packets = list(reader)
    assert len(packets) == 2
    assert all(isinstance(packet, CapturedPacket) for packet in packets)
    assert all(isinstance(packet.raw_data, bytes) for packet in packets)
    assert all(packet.timestamp > 0 for packet in packets)


def test_missing_pcap_file_raises_error(tmp_path):
    pcap_path = tmp_path / "missing.pcap"
    with pytest.raises(FileNotFoundError):
        PcapFileReader(pcap_path)


def test_invalid_pcap_raises_error(tmp_path):
    pcap_path = tmp_path / "invalid.pcap"
    pcap_path.write_bytes(b"this is not a valid pcap file")

    reader = PcapFileReader(pcap_path)

    with pytest.raises(PcapReadError):
        list(reader)


def test_empty_pcap_raises_error(tmp_path):
    pcap_path = tmp_path / "empty.pcap"
    pcap_path.write_bytes(b"")

    reader = PcapFileReader(pcap_path)

    with pytest.raises(PcapReadError):
        list(reader)
