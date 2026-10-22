from __future__ import annotations

import asyncio

from ..core.models import Finding, Severity
from ..core.oob import CallbackServer


async def run(ctx) -> None:
    if not getattr(ctx.settings, "aggressive", False):
        return
    server = CallbackServer()
    ok = await server.start()
    if not ok:
        return
    callback_base = f"http://{server.host}:{server.port}"
    params = ["url", "next", "redirect", "dest", "target", "uri", "callback"]
    try:
        for param in params:
            if not ctx.can_request():
                break
            token = server.new_token()
            payload = f"{callback_base}/{token}"
            ctx.increment()
            await ctx.http.get(f"https://{ctx.target}", params={param: payload}, timeout=ctx.settings.timeout)
        await asyncio.sleep(3)
        for param in params:
            # We cannot map token back easily; report if any callback received.
            pass
        if server.received:
            ctx.add_finding(Finding(
                id="oob-callback-received",
                title="Out-of-band callback received",
                severity=Severity.HIGH,
                confidence=0.9,
                asset=ctx.target,
                module="oob",
                description=f"Received callbacks: {', '.join(sorted(server.received))}",
                remediation="Investigate the triggering parameter and validate outbound requests.",
                tags=["oob", "ssrf", "blind"],
            ))
    finally:
        await server.stop()