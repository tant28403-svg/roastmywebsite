from __future__ import annotations

from ..core.models import Finding, Severity

TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
]


async def run(ctx) -> None:
    params = ["url", "next", "redirect", "dest", "target", "uri"]
    base = f"https://{ctx.target}"
    for param in params:
        for ssrf_target in TARGETS:
            if not ctx.can_request():
                return
            ctx.increment()
            resp = await ctx.http.get(base, params={param: ssrf_target}, timeout=ctx.settings.timeout)
            body = (resp.text or "").lower()
            if "ami-id" in body or "instance-id" in body or "root:x:" in body or "localhost" in body:
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
                break