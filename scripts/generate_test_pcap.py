#!/usr/bin/env python3
"""Generate a multi-protocol test PCAP for manual DPI demos."""

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from deep_packet_inspection.util.tls_builders import build_dns_query, build_tls_client_hello


def build_packets() -> list:
    packets = []
    tls_targets = [
        ("142.250.185.110", "www.youtube.com"),
        ("157.240.1.35", "www.facebook.com"),
        ("140.82.114.4", "github.com"),
        ("93.184.216.34", "www.example.com"),
    ]
    sport = 50000
    for dst_ip, sni in tls_targets:
        packets.append(
            Ether()
            / IP(src="192.168.1.100", dst=dst_ip)
            / TCP(sport=sport, dport=443)
            / Raw(build_tls_client_hello(sni))
        )
        sport += 1

    packets.append(
        Ether()
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=sport, dport=80)
        / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    sport += 1

    packets.append(
        Ether()
        / IP(src="192.168.1.100", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / Raw(build_dns_query("www.google.com"))
    )

    packets.append(
        Ether() / IP(src="192.168.1.50", dst="1.1.1.1") / TCP(sport=51000, dport=443) / Raw(b"")
    )
    return packets


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("test_dpi.pcap"),
        help="Output PCAP path (default: test_dpi.pcap)",
    )
    args = parser.parse_args()
    packets = build_packets()
    wrpcap(str(args.output), packets)
    print(f"Wrote {len(packets)} packets to {args.output}")


if __name__ == "__main__":
    main()
