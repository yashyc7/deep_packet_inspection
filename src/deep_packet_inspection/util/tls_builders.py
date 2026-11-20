"""Builders for synthetic TLS / DNS payloads (tests and demos)."""

from __future__ import annotations

import struct


def build_tls_client_hello(sni: str) -> bytes:
    """Build a minimal TLS 1.2 Client Hello containing an SNI extension."""

    sni_bytes = sni.encode("ascii")
    sni_entry = struct.pack(">BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

    supported_versions = struct.pack(">HHB", 0x002B, 3, 2) + struct.pack(">H", 0x0304)
    extensions = sni_ext + supported_versions
    extensions_data = struct.pack(">H", len(extensions)) + extensions

    client_version = struct.pack(">H", 0x0303)
    random_bytes = bytes(range(32))
    session_id = struct.pack("B", 0)
    cipher_suites = struct.pack(">H", 4) + struct.pack(">HH", 0x1301, 0x1302)
    compression = struct.pack("BB", 1, 0)

    client_hello_body = (
        client_version + random_bytes + session_id + cipher_suites + compression + extensions_data
    )

    handshake = struct.pack("B", 0x01)
    handshake += struct.pack(">I", len(client_hello_body))[1:]
    handshake += client_hello_body

    record = struct.pack("B", 0x16)
    record += struct.pack(">H", 0x0301)
    record += struct.pack(">H", len(handshake))
    record += handshake
    return record


def build_dns_query(domain: str) -> bytes:
    txid = struct.pack(">H", 0x1234)
    flags = struct.pack(">H", 0x0100)
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += struct.pack("B", len(label)) + label.encode("ascii")
    question += struct.pack("B", 0)
    question += struct.pack(">HH", 1, 1)
    return txid + flags + counts + question
