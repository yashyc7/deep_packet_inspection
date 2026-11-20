from dataclasses import dataclass

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    """Normalized metadata extracted from a network packet."""

    timestamp: float
    src_mac: str | None
    dst_mac: str | None
    src_ip: str | None
    dst_ip: str | None
    protocol: str
    src_port: int | None
    dst_port: int | None
    payload_size: int


class PacketParser:
    """Extract normalized metadata from raw network packet bytes."""

    def parse(self, timestamp: float, raw_data: bytes) -> ParsedPacket:
        packet = Ether(raw_data)

        src_mac = None
        dst_mac = None
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        protocol = "OTHER"
        payload_size = 0

        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = self._get_transport_protocol(ip_layer)

        elif IPv6 in packet:
            ip_layer = packet[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = self._get_transport_protocol(ip_layer)

        elif ARP in packet:
            protocol = "ARP"

        if TCP in packet:
            transport_layer = packet[TCP]
            src_port = transport_layer.sport
            dst_port = transport_layer.dport
            payload_size = len(bytes(transport_layer.payload))

        elif UDP in packet:
            transport_layer = packet[UDP]
            src_port = transport_layer.sport
            dst_port = transport_layer.dport
            payload_size = len(bytes(transport_layer.payload))

        return ParsedPacket(
            timestamp=timestamp,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            payload_size=payload_size,
        )

    @staticmethod
    def _get_transport_protocol(ip_layer: Packet) -> str:
        """Identify the transport protocol encapsulated in an IP packet."""

        if TCP in ip_layer:
            return "TCP"

        if UDP in ip_layer:
            return "UDP"

        return "OTHER"
