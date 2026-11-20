"""Classify a flow using payload inspection and port-based fallbacks."""

from __future__ import annotations

from deep_packet_inspection.flow.types import AppType, Flow, sni_to_app_type
from deep_packet_inspection.inspection.dns import extract_dns_query, is_dns_query
from deep_packet_inspection.inspection.http_host import extract_http_host
from deep_packet_inspection.inspection.sni import extract_sni
from deep_packet_inspection.parser.packet_parser import ParsedPacket


def classify_flow(flow: Flow, packet: ParsedPacket) -> None:
    """Update flow.app_type / flow.sni from the current packet when possible."""

    payload = packet.payload
    dst_port = packet.dst_port
    src_port = packet.src_port

    needs_deep_inspect = flow.app_type in {
        AppType.UNKNOWN,
        AppType.HTTPS,
        AppType.HTTP,
        AppType.TLS,
    }

    # TLS SNI (typically first client packet to port 443)
    if (
        needs_deep_inspect
        and not flow.sni
        and packet.protocol == "TCP"
        and payload
        and dst_port == 443
    ):
        sni = extract_sni(payload)
        if sni:
            flow.sni = sni
            flow.app_type = sni_to_app_type(sni)
            return

    # Cleartext HTTP Host
    if (
        needs_deep_inspect
        and not flow.sni
        and packet.protocol == "TCP"
        and payload
        and dst_port == 80
    ):
        host = extract_http_host(payload)
        if host:
            flow.sni = host
            mapped = sni_to_app_type(host)
            # Unrecognized cleartext hosts stay HTTP, not generic HTTPS.
            flow.app_type = AppType.HTTP if mapped == AppType.HTTPS else mapped
            return

    # DNS
    if flow.app_type == AppType.UNKNOWN and (dst_port == 53 or src_port == 53):
        flow.app_type = AppType.DNS
        if payload and is_dns_query(payload):
            query = extract_dns_query(payload)
            if query and not flow.sni:
                flow.sni = query
        return

    # Port-based fallback
    if flow.app_type == AppType.UNKNOWN:
        if dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif dst_port == 80:
            flow.app_type = AppType.HTTP
