"""TLS Client Hello Server Name Indication (SNI) extraction."""

from __future__ import annotations

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI = 0x0000
SNI_TYPE_HOSTNAME = 0x00


def _read_uint16_be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _read_uint24_be(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def is_tls_client_hello(payload: bytes) -> bool:
    """Return True when payload looks like a TLS Client Hello record."""

    if len(payload) < 9:
        return False
    if payload[0] != CONTENT_TYPE_HANDSHAKE:
        return False

    version = _read_uint16_be(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return False

    record_length = _read_uint16_be(payload, 3)
    if record_length > len(payload) - 5:
        return False

    return payload[5] == HANDSHAKE_CLIENT_HELLO


def extract_sni(payload: bytes) -> str | None:
    """Extract the hostname from a TLS Client Hello SNI extension."""

    if not is_tls_client_hello(payload):
        return None

    # Skip TLS record header (5) + handshake type (1) + handshake length (3)
    offset = 5 + 4
    # Client version (2) + random (32)
    offset += 2 + 32
    if offset >= len(payload):
        return None

    session_id_length = payload[offset]
    offset += 1 + session_id_length

    if offset + 2 > len(payload):
        return None
    cipher_suites_length = _read_uint16_be(payload, offset)
    offset += 2 + cipher_suites_length

    if offset >= len(payload):
        return None
    compression_methods_length = payload[offset]
    offset += 1 + compression_methods_length

    if offset + 2 > len(payload):
        return None
    extensions_length = _read_uint16_be(payload, offset)
    offset += 2
    extensions_end = min(offset + extensions_length, len(payload))

    while offset + 4 <= extensions_end:
        extension_type = _read_uint16_be(payload, offset)
        extension_length = _read_uint16_be(payload, offset + 2)
        offset += 4

        if offset + extension_length > extensions_end:
            break

        if extension_type == EXTENSION_SNI:
            if extension_length < 5:
                break
            sni_type = payload[offset + 2]
            sni_length = _read_uint16_be(payload, offset + 3)
            if sni_type != SNI_TYPE_HOSTNAME:
                break
            if sni_length > extension_length - 5:
                break
            start = offset + 5
            end = start + sni_length
            if end > len(payload):
                break
            hostname = payload[start:end].decode("ascii", errors="ignore")
            return hostname or None

        offset += extension_length

    return None
