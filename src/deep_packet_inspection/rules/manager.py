"""Blocking rules for IP, application, and domain matching."""

from __future__ import annotations

from deep_packet_inspection.flow.types import AppType, parse_app_type


class RuleManager:
    """Evaluate whether a flow should be blocked."""

    def __init__(self) -> None:
        self._blocked_ips: set[str] = set()
        self._blocked_apps: set[AppType] = set()
        self._blocked_domains: list[str] = []

    def block_ip(self, ip: str) -> None:
        self._blocked_ips.add(ip.strip())

    def block_app(self, app_name: str) -> AppType:
        app = parse_app_type(app_name)
        if app is None:
            raise ValueError(f"Unknown application name: {app_name}")
        self._blocked_apps.add(app)
        return app

    def block_domain(self, domain: str) -> None:
        self._blocked_domains.append(domain.strip().lower())

    @property
    def blocked_ips(self) -> set[str]:
        return set(self._blocked_ips)

    @property
    def blocked_apps(self) -> set[AppType]:
        return set(self._blocked_apps)

    @property
    def blocked_domains(self) -> list[str]:
        return list(self._blocked_domains)

    def is_blocked(
        self,
        src_ip: str | None,
        app_type: AppType,
        sni: str | None,
    ) -> bool:
        if src_ip is not None and src_ip in self._blocked_ips:
            return True
        if app_type in self._blocked_apps:
            return True
        if sni:
            lower = sni.lower()
            for domain in self._blocked_domains:
                if domain in lower:
                    return True
        return False
