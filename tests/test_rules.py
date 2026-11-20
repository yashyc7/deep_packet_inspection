import pytest

from deep_packet_inspection.flow.types import AppType
from deep_packet_inspection.rules.manager import RuleManager


def test_block_ip():
    rules = RuleManager()
    rules.block_ip("192.168.1.50")
    assert rules.is_blocked("192.168.1.50", AppType.UNKNOWN, None)
    assert not rules.is_blocked("192.168.1.100", AppType.UNKNOWN, None)


def test_block_app():
    rules = RuleManager()
    rules.block_app("YouTube")
    assert rules.is_blocked("1.1.1.1", AppType.YOUTUBE, "www.youtube.com")
    assert not rules.is_blocked("1.1.1.1", AppType.FACEBOOK, "www.facebook.com")


def test_block_domain_substring():
    rules = RuleManager()
    rules.block_domain("youtube")
    assert rules.is_blocked("1.1.1.1", AppType.HTTPS, "www.youtube.com")
    assert not rules.is_blocked("1.1.1.1", AppType.HTTPS, "www.example.com")


def test_unknown_app_raises():
    rules = RuleManager()
    with pytest.raises(ValueError, match="Unknown application"):
        rules.block_app("NotARealApp")
