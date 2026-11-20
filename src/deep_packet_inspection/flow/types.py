"""Core DPI types: five-tuple, flow state, and application classification."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class AppType(Enum):
    """Application classification derived from ports, SNI, or Host headers."""

    UNKNOWN = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    TLS = auto()
    QUIC = auto()
    GOOGLE = auto()
    FACEBOOK = auto()
    YOUTUBE = auto()
    TWITTER = auto()
    INSTAGRAM = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    WHATSAPP = auto()
    TELEGRAM = auto()
    TIKTOK = auto()
    SPOTIFY = auto()
    ZOOM = auto()
    DISCORD = auto()
    GITHUB = auto()
    CLOUDFLARE = auto()


# Display names aligned with the original C++ engine CLI / reports.
_APP_DISPLAY: dict[AppType, str] = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}

# Specific apps before generic platforms (YouTube before Google, Instagram before Facebook).
_SNI_RULES: list[tuple[AppType, tuple[str, ...]]] = [
    (AppType.YOUTUBE, ("youtube", "ytimg", "youtu.be", "googlevideo")),
    (AppType.INSTAGRAM, ("instagram", "cdninstagram")),
    (AppType.WHATSAPP, ("whatsapp", "wa.me")),
    (AppType.FACEBOOK, ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")),
    (AppType.TWITTER, ("twitter", "twimg", "x.com", "t.co")),
    (AppType.NETFLIX, ("netflix", "nflxvideo", "nflximg")),
    (AppType.AMAZON, ("amazon", "amazonaws", "cloudfront")),
    (AppType.MICROSOFT, ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")),
    (AppType.APPLE, ("apple", "icloud", "mzstatic", "itunes")),
    (AppType.TELEGRAM, ("telegram", "t.me")),
    (AppType.TIKTOK, ("tiktok", "tiktokcdn", "musical.ly", "bytedance")),
    (AppType.SPOTIFY, ("spotify", "scdn.co")),
    (AppType.ZOOM, ("zoom.us", "zoom.com")),
    (AppType.DISCORD, ("discord", "discordapp")),
    (AppType.GITHUB, ("github", "githubusercontent")),
    (AppType.CLOUDFLARE, ("cloudflare",)),
    (AppType.GOOGLE, ("google", "gstatic", "googleapis", "gvt1", "ggpht")),
]


@dataclass(frozen=True, slots=True)
class FiveTuple:
    """Uniquely identifies a unidirectional network flow."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.protocol})"


@dataclass
class Flow:
    """Per-connection state accumulated across packets."""

    key: FiveTuple
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    sni: str | None = None
    app_type: AppType = AppType.UNKNOWN
    blocked: bool = False


@dataclass
class ProcessingStats:
    """Aggregate counters for a pipeline run."""

    total_packets: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    flow_count: int = 0
    app_counts: dict[AppType, int] = field(default_factory=dict)
    detected_domains: dict[str, AppType] = field(default_factory=dict)


def app_type_to_string(app_type: AppType) -> str:
    return _APP_DISPLAY.get(app_type, "Unknown")


def parse_app_type(name: str) -> AppType | None:
    """Resolve a CLI app name (case-insensitive) to AppType."""

    needle = name.strip().lower()
    for app, label in _APP_DISPLAY.items():
        if label.lower() == needle or app.name.lower() == needle:
            return app
    # Common aliases
    aliases = {
        "twitter": AppType.TWITTER,
        "x": AppType.TWITTER,
        "youtube": AppType.YOUTUBE,
        "fb": AppType.FACEBOOK,
    }
    return aliases.get(needle)


def sni_to_app_type(sni: str) -> AppType:
    """Map a domain/SNI string to an application type."""

    if not sni:
        return AppType.UNKNOWN

    lower = sni.lower()
    for app, patterns in _SNI_RULES:
        if any(pattern in lower for pattern in patterns):
            return app
    return AppType.HTTPS
