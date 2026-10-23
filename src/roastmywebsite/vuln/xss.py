from __future__ import annotations

from ..core.models import Finding, Severity

PAYLOAD = "<script>alert(1)</script>"
BENIGN = "rmw-baseline-check-12345"


async def run(ctx) -> None:
    params = ["q", "search", "name", "redirect", "next", "return"]
    base = f"https://{ctx.target}"
    for param in params:
        if not ctx.can_request():
            return
        ctx.increment()
        baseline_resp = await ctx.http.get(base, params={param: BENIGN}, timeout=ctx.settings.timeout)
        baseline_body = baseline_resp.text or ""
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(base, params={param: PAYLOAD}, timeout=ctx.settings.timeout)
        body = resp.text or ""
        # Only flag if the payload is reflected AND it wasn't already reflected
        # in the benign baseline (which would indicate the server echoes all input).
        if PAYLOAD in body and PAYLOAD not in baseline_body:
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