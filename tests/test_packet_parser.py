from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from deep_packet_inspection.parser.packet_parser import (
    PacketParser,
    ParsedPacket,
)


def test_parse_tcp_packet():
    raw_packet = bytes(
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=51515, dport=443)
        / Raw(b"Hello")
    )

    parser = PacketParser()
    result = parser.parse(timestamp=1234.5, raw_data=raw_packet)

    assert isinstance(result, ParsedPacket)
    assert result.timestamp == 1234.5
    assert result.src_ip == "192.168.1.10"
    assert result.dst_ip == "8.8.8.8"
    assert result.protocol == "TCP"
    assert result.src_port == 51515
    assert result.dst_port == 443
    assert result.payload_size == 5
    assert result.payload == b"Hello"


def test_parse_udp_packet():
    raw_packet = bytes(
        Ether() / IP(src="10.0.0.2", dst="1.1.1.1") / UDP(sport=53000, dport=53) / Raw(b"DNS query")
    )

    result = PacketParser().parse(timestamp=10.0, raw_data=raw_packet)

    assert result.protocol == "UDP"
    assert result.src_port == 53000
    assert result.dst_port == 53
    assert result.payload_size == len(b"DNS query")
    assert result.payload == b"DNS query"


def test_parse_arp_packet():
    raw_packet = bytes(Ether() / ARP())

    result = PacketParser().parse(timestamp=20.0, raw_data=raw_packet)

    assert result.protocol == "ARP"
    assert result.src_mac is not None
    assert result.dst_mac is not None
    assert result.src_ip is None
    assert result.dst_ip is None
    assert result.src_port is None
    assert result.dst_port is None
    assert result.payload == b""


def test_parse_ipv6_tcp_packet():
    raw_packet = bytes(
        Ether(
            src="00:11:22:33:44:55",
            dst="66:77:88:99:aa:bb",
        )
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=12345, dport=443)
        / Raw(b"IPv6 test")
    )

    result = PacketParser().parse(timestamp=30.0, raw_data=raw_packet)

    assert result.src_ip == "2001:db8::1"
    assert result.dst_ip == "2001:db8::2"
    assert result.protocol == "TCP"
    assert result.src_port == 12345
    assert result.dst_port == 443
    assert result.payload_size == len(b"IPv6 test")
    assert result.payload == b"IPv6 test"
