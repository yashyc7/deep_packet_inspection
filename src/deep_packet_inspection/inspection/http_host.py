"""HTTP Host header extraction for cleartext HTTP requests."""

from __future__ import annotations

_HTTP_METHOD_PREFIXES = (
    b"GET ",
    b"POST",
    b"PUT ",
    b"HEAD",
    b"DELE",
    b"PATC",
    b"OPTI",
)


def is_http_request(payload: bytes) -> bool:
    if len(payload) < 4:
        return False
    return any(payload.startswith(prefix) for prefix in _HTTP_METHOD_PREFIXES)


def extract_http_host(payload: bytes) -> str | None:
    """Extract the Host header value (without port) from an HTTP request."""

    if not is_http_request(payload):
        return None

    text = payload.decode("latin-1", errors="ignore")

    for line in text.split("\r\n"):
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() == "host":
            host = value.strip()
            if not host:
                return None
            # Drop optional port
            if host.startswith("["):
                # IPv6 literal [::1]:80
                closing = host.find("]")
                if closing != -1:
                    return host[1:closing]
            if ":" in host:
                host = host.rsplit(":", 1)[0]
            return host or None
    return None
