from deep_packet_inspection.flow.types import AppType, sni_to_app_type
from deep_packet_inspection.inspection.dns import extract_dns_query, is_dns_query
from deep_packet_inspection.inspection.http_host import extract_http_host, is_http_request
from deep_packet_inspection.inspection.sni import extract_sni, is_tls_client_hello
from tests.helpers import build_dns_query, build_tls_client_hello


def test_extract_sni_from_client_hello():
    payload = build_tls_client_hello("www.youtube.com")
    assert is_tls_client_hello(payload)
    assert extract_sni(payload) == "www.youtube.com"


def test_extract_sni_rejects_non_tls():
    assert extract_sni(b"GET / HTTP/1.1\r\n") is None
    assert not is_tls_client_hello(b"not tls")


def test_extract_http_host():
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert is_http_request(payload)
    assert extract_http_host(payload) == "example.com"


def test_extract_http_host_strips_port():
    payload = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
    assert extract_http_host(payload) == "example.com"


def test_extract_dns_query():
    payload = build_dns_query("www.google.com")
    assert is_dns_query(payload)
    assert extract_dns_query(payload) == "www.google.com"


def test_sni_to_app_type_mapping():
    assert sni_to_app_type("www.youtube.com") == AppType.YOUTUBE
    assert sni_to_app_type("www.facebook.com") == AppType.FACEBOOK
    assert sni_to_app_type("github.com") == AppType.GITHUB
    assert sni_to_app_type("unknown.example") == AppType.HTTPS
    assert sni_to_app_type("") == AppType.UNKNOWN
