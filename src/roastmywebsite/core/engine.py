from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .events import EventBus
from .models import Asset, Finding, ScanResult
from .scope import ScopeConfig

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
ORANGE = "\033[38;5;208m"
GRAY = "\033[90m"


def _sev_color(severity) -> str:
    """Return ANSI color code for finding severity."""
    sev = severity.value if hasattr(severity, 'value') else str(severity).lower()
    if sev == "critical":
        return RED
    if sev == "high":
        return ORANGE
    if sev == "medium":
        return YELLOW
    if sev == "low":
        return BLUE
    return GRAY


@dataclass
class ModuleContext:
    target: str
    mode: str
    settings: Any
    scope: ScopeConfig
    http: Any
    event_bus: EventBus
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    request_count: int = 0
    waf_type: str | None = None
    # Cross-cutting: request dedup and response fingerprinting
    _seen_requests: set = field(default_factory=set)
    _seen_response_hashes: set = field(default_factory=set)
    _seen_findings: set = field(default_factory=set)

    def is_duplicate_request(self, method: str, url: str, params: Any = None) -> bool:
        import hashlib
        key = f"{method}:{url}:{params}"
        h = hashlib.md5(key.encode()).hexdigest()
        if h in self._seen_requests:
            return True
        self._seen_requests.add(h)
        return False

    def is_duplicate_response(self, body: str) -> bool:
        import hashlib
        h = hashlib.md5((body or "").encode()).hexdigest()
        if h in self._seen_response_hashes:
            return True
        self._seen_response_hashes.add(h)
        return False

    def is_duplicate_finding(self, module: str, asset: str, title: str) -> bool:
        key = f"{module}:{asset}:{title}"
        if key in self._seen_findings:
            return True
        self._seen_findings.add(key)
        return False

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.event_bus.emit("finding", finding)

    def add_asset(self, asset: Asset) -> None:
        self.assets.append(asset)
        self.event_bus.emit("asset", asset)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.event_bus.emit("finding", finding)

    def can_request(self) -> bool:
        return self.request_count < self.scope.max_requests

    def increment(self) -> None:
        self.request_count += 1


ModuleFunc = Callable[[ModuleContext], Awaitable[None]]


class ScanEngine:
    def __init__(self, event_bus: EventBus | None = None):
        self.event_bus = event_bus or EventBus()
        self.modules: dict[str, ModuleFunc] = {}

    def register(self, name: str, func: ModuleFunc) -> None:
        self.modules[name] = func

    async def run(
        self,
        target: str,
        mode: str,
        settings: Any,
        module_names: list[str],
        http_client_factory: Callable[[], Any],
    ) -> ScanResult:
        scan_id = str(uuid.uuid4())
        started = datetime.utcnow()
        scope = scope_for_target_safe(target, settings)
        async with http_client_factory() as http:
            ctx = ModuleContext(
                target=target,
                mode=mode,
                settings=settings,
                scope=scope,
                http=http,
                event_bus=self.event_bus,
            )
            # Run independent modules in parallel for better performance
            async def _run_module(name: str) -> None:
                if name not in self.modules:
                    return
                self.event_bus.emit("module_start", name)
                try:
                    await self.modules[name](ctx)
                except Exception as exc:
                    self.event_bus.emit("module_error", {"module": name, "error": str(exc)})
                self.event_bus.emit("module_done", name)

            # Group modules into batches to limit concurrency and avoid overwhelming the target
            batch_size = 1
            for i in range(0, len(module_names), batch_size):
                batch = module_names[i:i + batch_size]
                await asyncio.gather(*[_run_module(name) for name in batch], return_exceptions=True)
            finished = datetime.utcnow()
            # End-of-scan console summary so results aren't lost behind proxychains / scrolling
            print(f"\n{BOLD}{CYAN}========== SCAN SUMMARY =========={RESET}")
            print(f"{WHITE}Target: {target}  Mode: {mode}  Scan ID: {scan_id}{RESET}")
            print(f"{GREEN}Requests: {ctx.request_count}  Assets: {len(ctx.assets)}  Findings: {len(ctx.findings)}{RESET}")
            for a in ctx.assets:
                status = (a.metadata or {}).get("status") if hasattr(a, "metadata") else None
                if status == 200:
                    acolor = GREEN
                elif status == 404:
                    acolor = RED
                elif status in (301, 302, 401, 403):
                    acolor = YELLOW
                else:
                    acolor = BLUE
                print(f"  {acolor}[ASSET]{RESET} {a}")
            for f in ctx.findings:
                color = _sev_color(f.severity)
                sev_str = f.severity.value if hasattr(f.severity, 'value') else f.severity
                print(f"  {color}[FINDING]{RESET} {f.id} | {f.title} | severity={color}{sev_str}{RESET} | asset={f.asset} | module={f.module}")
            print(f"{BOLD}{CYAN}=================================={RESET}\n")
            result = ScanResult(
                id=scan_id,
                target=target,
                started_at=started,
                finished_at=finished,
                mode=mode,
                assets=ctx.assets,
                findings=ctx.findings,
                metadata={"request_count": ctx.request_count},
            )
            self.event_bus.emit("scan_done", result)
            return result


def scope_for_target_safe(target: str, settings: Any) -> ScopeConfig:
    from .scope import scope_for_target

    include = getattr(settings, "scope_include", None) or None
    scope = scope_for_target(target, include)
    scope.rate_limit = getattr(settings, "rate_limit", scope.rate_limit)
    scope.max_requests = getattr(settings, "max_requests", scope.max_requests)
    return scope