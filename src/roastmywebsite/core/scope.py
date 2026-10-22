from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ScopeConfig:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    max_requests: int = 5000
    rate_limit: float = 5.0


def normalize_host(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or value
    return value.rstrip(".")


def host_matches(host: str, pattern: str) -> bool:
    host = normalize_host(host)
    pattern = pattern.strip().lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)
    if re.search(r"\d", pattern) and "/" in pattern:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            ip = ipaddress.ip_address(host)
            return ip in network
        except ValueError:
            pass
    return host == pattern


def in_scope(host: str, scope: ScopeConfig) -> bool:
    host = normalize_host(host)
    if scope.exclude and any(host_matches(host, p) for p in scope.exclude):
        return False
    if not scope.include:
        return True
    return any(host_matches(host, p) for p in scope.include)


def scope_for_target(target: str, settings_scope_include: list[str] | None = None) -> ScopeConfig:
    host = normalize_host(target)
    include = settings_scope_include or [host, f"*.{host}"]
    return ScopeConfig(include=include, exclude=[])