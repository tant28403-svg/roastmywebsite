from __future__ import annotations

from ..core.models import Finding, Severity

TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
]

# Specific indicators that only appear in actual cloud metadata or internal
# resource responses, not in ordinary HTML pages.
SSRF_INDICATORS = ("ami-id", "instance-id", "root:x:", "ami-launch-index", "security-credentials")


async def run(ctx) -> None:
    params = ["url", "next", "redirect", "dest", "target", "uri"]
    base = f"https://{ctx.target}"
    for param in params:
        for ssrf_target in TARGETS:
            if not ctx.can_request():
                return
            ctx.increment()
            # Baseline with a benign value to know what a normal response looks like.
            baseline_resp = await ctx.http.get(base, params={param: "https://example.com"}, timeout=ctx.settings.timeout)
            baseline_body = (baseline_resp.text or "").lower()
            if not ctx.can_request():
                return
            ctx.increment()
            resp = await ctx.http.get(base, params={param: ssrf_target}, timeout=ctx.settings.timeout)
            body = (resp.text or "").lower()
            # Only flag if a specific SSRF indicator appears in the response
            # AND was not already present in the benign baseline.
            new_indicators = [ind for ind in SSRF_INDICATORS if ind in body and ind not in baseline_body]
            if new_indicators:
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