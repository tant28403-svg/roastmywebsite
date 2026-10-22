from __future__ import annotations

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
            for name in module_names:
                if name not in self.modules:
                    continue
                self.event_bus.emit("module_start", name)
                try:
                    await self.modules[name](ctx)
                except Exception as exc:
                    self.event_bus.emit("module_error", {"module": name, "error": str(exc)})
                self.event_bus.emit("module_done", name)
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