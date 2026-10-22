from __future__ import annotations

from ..core.models import Finding, Severity

PAYLOAD = "<script>alert(1)</script>"


async def run(ctx) -> None:
    params = ["q", "search", "name", "redirect", "next", "return"]
    base = f"https://{ctx.target}"
    for param in params:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(base, params={param: PAYLOAD}, timeout=ctx.settings.timeout)
        if PAYLOAD in (resp.text or ""):
            ctx.add_finding(Finding(
                id=f"reflected-xss-{param}",
                title=f"Potential reflected XSS via '{param}' parameter",
                severity=Severity.MEDIUM,
                confidence=0.75,
                asset=f"{base}?{param}={PAYLOAD}",
                module="xss",
                description="Payload reflected unencoded in response.",
                remediation="Apply context-aware output encoding and CSP.",
                tags=["xss"],
            ))