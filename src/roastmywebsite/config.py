from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


def xdg_dir(kind: str, app: str = "roastmywebsite") -> Path:
    base = os.environ.get(f"XDG_{kind.upper()}_HOME")
    if not base:
        home = Path.home()
        base = home / (".config" if kind == "config" else ".cache" if kind == "cache" else ".local/share")
    path = Path(base) / app
    path.mkdir(parents=True, exist_ok=True)
    return path


CONFIG_DIR = xdg_dir("config")
CACHE_DIR = xdg_dir("cache")
DATA_DIR = xdg_dir("data")
DB_PATH = DATA_DIR / "roastmywebsite.db"
REPORT_DIR = DATA_DIR / "reports"


@dataclass
class ScanSettings:
    rate_limit: float = 5.0
    max_requests: int = 5000
    timeout: float = 10.0
    concurrency: int = 20
    proxy: str | None = None
    verify_tls: bool = True
    user_agent: str = "RoastMyWebsite/0.1 (+https://github.com/your-org/roast-my-website)"
    aggressive: bool = False
    permission_acknowledged: bool = False
    oob_domain: str | None = None
    oob_http_port: int = 8989
    oob_dns_port: int = 5353
    scope_include: list[str] = field(default_factory=list)
    scope_exclude: list[str] = field(default_factory=list)
    api_keys: dict[str, str] = field(default_factory=dict)
    # Tool selection
    ports_tool: str = "auto"
    subdomain_tool: str = "auto"
    # Nuclei configuration
    nuclei_templates: str | None = None
    nuclei_tags: str | None = None
    nuclei_severity: str | None = None
    nuclei_exclude_tags: str | None = None


def load_config(path: Path | None = None) -> ScanSettings:
    path = path or (CONFIG_DIR / "config.yaml")
    if not path.exists():
        return ScanSettings()
    with path.open("r", encoding="utf-8") as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}
    settings = ScanSettings()
    for key, value in raw.items():
        if hasattr(settings, key):
            setattr(settings, key, value)
    return settings


def save_config(settings: ScanSettings, path: Path | None = None) -> None:
    path = path or (CONFIG_DIR / "config.yaml")
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(settings.__dict__, f, sort_keys=False)