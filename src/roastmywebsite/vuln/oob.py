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
    # Map each token to the parameter that triggered it.
    token_to_param: dict[str, str] = {}
    try:
        for param in params:
            if not ctx.can_request():
                break
            token = server.new_token()
            token_to_param[token] = param
            payload = f"{callback_base}/{token}"
            ctx.increment()
            await ctx.http.get(f"https://{ctx.target}", params={param: payload}, timeout=ctx.settings.timeout)
        await asyncio.sleep(3)
        # Report per-parameter findings based on which tokens were received.
        received_params = {token_to_param[t] for t in server.received if t in token_to_param}
        for param in received_params:
            ctx.add_finding(Finding(
                id=f"oob-callback-{param}",
                title=f"Out-of-band callback received via '{param}' parameter",
                severity=Severity.HIGH,
                confidence=0.9,
                asset=f"https://{ctx.target}",
                module="oob",
                description=f"An out-of-band HTTP callback was triggered through the '{param}' parameter.",
                remediation="Validate and allowlist outbound URLs; block external callbacks.",
                tags=["oob", "ssrf"],
            ))
    finally:
        await server.stop()