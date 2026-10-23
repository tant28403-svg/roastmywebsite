from __future__ import annotations

import asyncio

from ..core.models import Finding, Severity

TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
]

SSRF_INDICATORS = ("ami-id", "instance-id", "root:x:", "ami-launch-index", "security-credentials")


async def _probe(ctx, base: str, param: str, ssrf_target: str) -> bool:
    if not ctx.can_request():
        return False
    ctx.increment()
    baseline_resp = await ctx.http.get(base, params={param: "https://example.com"}, timeout=ctx.settings.timeout)
    baseline_body = (baseline_resp.text or "").lower()
    if not ctx.can_request():
        return False
    ctx.increment()
    resp = await ctx.http.get(base, params={param: ssrf_target}, timeout=ctx.settings.timeout)
    body = (resp.text or "").lower()
    new_indicators = [ind for ind in SSRF_INDICATORS if ind in body and ind not in baseline_body]
    return len(new_indicators) > 0


async def run(ctx) -> None:
    params = ["url", "next", "redirect", "dest", "target", "uri"]
    base = f"https://{ctx.target}"

    async def _probe_param(param: str) -> None:
        for ssrf_target in TARGETS:
            if not ctx.can_request():
                return
            found = await _probe(ctx, base, param, ssrf_target)
            if found:
                ctx.add_finding(Finding(
                    id=f"ssrf-{param}",
                    title=f"Potential SSRF via '{param}' parameter",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    asset=f"{base}?{param}={ssrf_target}",
                    module="ssrf",
                    description="Response suggests internal resource access.",
                    remediation="Validate and allowlist outbound URLs; block internal ranges.",
                    tags=["ssrf"],
                ))
                return

    tasks = [_probe_param(param) for param in params]
    await asyncio.gather(*tasks, return_exceptions=True)