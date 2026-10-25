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
        if self.is_duplicate_finding(finding.module, finding.asset, finding.title):
            return
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
            batch_size = 4
            for i in range(0, len(module_names), batch_size):
                batch = module_names[i:i + batch_size]
                await asyncio.gather(*[_run_module(name) for name in batch], return_exceptions=True)
            finished = datetime.utcnow()
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