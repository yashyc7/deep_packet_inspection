"""DNS query name extraction (UDP/TCP DNS request QNAME)."""

from __future__ import annotations


def is_dns_query(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    # QR bit must be 0 (query)
    if payload[2] & 0x80:
        return False
    qdcount = (payload[4] << 8) | payload[5]
    return qdcount > 0


def extract_dns_query(payload: bytes) -> str | None:
    """Extract the first queried domain name from a DNS query."""

    if not is_dns_query(payload):
        return None

    offset = 12
    labels: list[str] = []

    while offset < len(payload):
        label_length = payload[offset]
        if label_length == 0:
            break
        if label_length > 63:
            # Compression pointer — stop rather than mis-parse
            break
        offset += 1
        if offset + label_length > len(payload):
            return None
        labels.append(payload[offset : offset + label_length].decode("ascii", errors="ignore"))
        offset += label_length

    domain = ".".join(label for label in labels if label)
    return domain or None
