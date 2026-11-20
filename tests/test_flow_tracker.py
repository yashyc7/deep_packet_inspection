from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from deep_packet_inspection.flow.tracker import FlowTracker
from deep_packet_inspection.parser.packet_parser import PacketParser


def _tcp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes = b"x") -> bytes:
    return bytes(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(payload))


def test_same_five_tuple_aggregates_into_one_flow():
    parser = PacketParser()
    tracker = FlowTracker()
    frame = _tcp_frame("192.168.1.10", "8.8.8.8", 51515, 443, b"ab")

    for ts in (1.0, 2.0):
        packet = parser.parse(ts, frame)
        flow = tracker.update(packet, frame_size=len(frame))
        assert flow is not None

    assert len(tracker) == 1
    flow = tracker.flows()[0]
    assert flow.packet_count == 2
    assert flow.byte_count == len(frame) * 2
    assert flow.first_seen == 1.0
    assert flow.last_seen == 2.0


def test_reverse_direction_is_separate_unidirectional_flow():
    parser = PacketParser()
    tracker = FlowTracker()

    forward = _tcp_frame("192.168.1.10", "8.8.8.8", 51515, 443)
    reverse = _tcp_frame("8.8.8.8", "192.168.1.10", 443, 51515)

    tracker.update(parser.parse(1.0, forward), len(forward))
    tracker.update(parser.parse(2.0, reverse), len(reverse))

    assert len(tracker) == 2


def test_arp_does_not_create_flow():
    from scapy.layers.l2 import ARP

    parser = PacketParser()
    tracker = FlowTracker()
    frame = bytes(Ether() / ARP())
    packet = parser.parse(1.0, frame)

    assert tracker.update(packet, len(frame)) is None
    assert len(tracker) == 0
