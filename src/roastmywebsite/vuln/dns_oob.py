from __future__ import annotations

import asyncio

from ..core.models import Finding, Severity
from ..core.oob import CallbackServer, DnsCallbackServer


async def run(ctx) -> None:
    domain = getattr(ctx.settings, "oob_domain", None)
    if not domain:
        return
    http_port = getattr(ctx.settings, "oob_http_port", 8989)
    dns_port = getattr(ctx.settings, "oob_dns_port", 5353)
    http_server = CallbackServer(port=http_port)
    dns_server = DnsCallbackServer(port=dns_port, domain=domain)
    if not await http_server.start():
        return
    await dns_server.start()
    token = CallbackServer.new_token()
    callback_host = f"{token}.{domain}"
    params = ["url", "next", "redirect", "dest", "target", "uri", "callback", "dns"]
    try:
        for param in params:
            if not ctx.can_request():
                break
            ctx.increment()
            await ctx.http.get(f"https://{ctx.target}", params={param: f"http://{callback_host}/"}, timeout=ctx.settings.timeout)
            ctx.increment()
            await ctx.http.get(f"https://{ctx.target}", params={param: callback_host}, timeout=ctx.settings.timeout)
        await asyncio.sleep(3)
        if http_server.got(token) or dns_server.got(token) or dns_server.got(callback_host):
            ctx.add_finding(Finding(
                id="dns-oob-callback",
                title="DNS/HTTP out-of-band callback received",
                severity=Severity.HIGH,
                confidence=0.9,
                asset=ctx.target,
                module="dns_oob",
                description=f"Callback token {token} was observed via {'HTTP' if http_server.got(token) else 'DNS'}.",
                remediation="Investigate the triggering parameter and validate outbound requests.",
                tags=["oob", "dns", "ssrf"],
            ))
    finally:
        await http_server.stop()
        await dns_server.stop()