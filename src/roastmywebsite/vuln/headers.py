from __future__ import annotations

from ..core.models import Finding, Severity

REQUIRED_HEADERS = {
    "strict-transport-security": ("Missing HSTS header", Severity.MEDIUM),
    "content-security-policy": ("Missing Content-Security-Policy header", Severity.MEDIUM),
    "x-frame-options": ("Missing X-Frame-Options header", Severity.LOW),
    "x-content-type-options": ("Missing X-Content-Type-Options header", Severity.LOW),
    "referrer-policy": ("Missing Referrer-Policy header", Severity.LOW),
    "permissions-policy": ("Missing Permissions-Policy header", Severity.LOW),
    "x-xss-protection": ("Missing X-XSS-Protection header", Severity.LOW),
    "cache-control": ("Missing Cache-Control header", Severity.LOW),
    "expect-ct": ("Missing Expect-CT header", Severity.LOW),
}


async def run(ctx) -> None:
    if not ctx.can_request():
        return
    ctx.increment()
    resp = await ctx.http.get(f"https://{ctx.target}", timeout=ctx.settings.timeout)
    if not resp.ok:
        ctx.increment()
        resp = await ctx.http.get(f"http://{ctx.target}", timeout=ctx.settings.timeout)
    if not resp.ok:
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for name, (title, sev) in REQUIRED_HEADERS.items():
        if name not in headers:
            ctx.add_finding(Finding(
                id=f"header-missing-{name}",
                title=title,
                severity=sev,
                confidence=1.0,
                asset=str(resp.url),
                module="headers",
                description=f"The response did not include the {name} header.",
                remediation=f"Add a {name} header to all responses.",
                tags=["misconfiguration", "headers"],
            ))
    # Cookie flags
    raw_cookies = resp.headers.get("set-cookie", "")
    if raw_cookies:
        low = raw_cookies.lower()
        if "httponly" not in low:
            ctx.add_finding(Finding(id="cookie-httponly", title="Cookie missing HttpOnly flag", severity=Severity.LOW, confidence=0.9, asset=str(resp.url), module="headers", remediation="Set HttpOnly on session cookies.", tags=["cookie"]))
        if "secure" not in low:
            ctx.add_finding(Finding(id="cookie-secure", title="Cookie missing Secure flag", severity=Severity.LOW, confidence=0.9, asset=str(resp.url), module="headers", remediation="Set Secure on session cookies.", tags=["cookie"]))
        if "samesite" not in low:
            ctx.add_finding(Finding(id="cookie-samesite", title="Cookie missing SameSite attribute", severity=Severity.LOW, confidence=0.9, asset=str(resp.url), module="headers", remediation="Set SameSite=Lax or Strict.", tags=["cookie"]))

    # CORS misconfiguration
    cors_origin = headers.get("access-control-allow-origin", "")
    if cors_origin == "*":
        ctx.add_finding(Finding(
            id="cors-wildcard",
            title="CORS allows any origin (wildcard)",
            severity=Severity.MEDIUM,
            confidence=1.0,
            asset=str(resp.url),
            module="headers",
            description="Access-Control-Allow-Origin is set to *, allowing any domain to read responses.",
            remediation="Restrict CORS to specific trusted origins.",
            tags=["cors", "misconfiguration"],
        ))

    # HSTS preload check
    hsts = headers.get("strict-transport-security", "")
    if hsts and "preload" not in hsts.lower():
        ctx.add_finding(Finding(
            id="hsts-no-preload",
            title="HSTS preload directive missing",
            severity=Severity.LOW,
            confidence=0.9,
            asset=str(resp.url),
            module="headers",
            description="HSTS header does not include the preload directive.",
            remediation="Add 'preload' to the HSTS header and submit to the HSTS preload list.",
            tags=["hsts", "tls"],
        ))

    # Server information disclosure
    server = headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        ctx.add_finding(Finding(
            id="server-version-disclosure",
            title="Server version disclosed",
            severity=Severity.LOW,
            confidence=0.9,
            asset=str(resp.url),
            module="headers",
            description=f"Server header reveals version: {server}",
            remediation="Remove or generalize the Server header.",
            tags=["information-disclosure"],
        ))

    # CSP analysis
    csp = headers.get("content-security-policy", "")
    if csp:
        csp_lower = csp.lower()
        if "unsafe-inline" in csp_lower:
            ctx.add_finding(Finding(
                id="csp-unsafe-inline",
                title="CSP allows unsafe-inline",
                severity=Severity.MEDIUM,
                confidence=1.0,
                asset=str(resp.url),
                module="headers",
                description="Content-Security-Policy includes 'unsafe-inline', weakening XSS protection.",
                remediation="Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
                tags=["csp", "xss", "misconfiguration"],
            ))
        if "unsafe-eval" in csp_lower:
            ctx.add_finding(Finding(
                id="csp-unsafe-eval",
                title="CSP allows unsafe-eval",
                severity=Severity.MEDIUM,
                confidence=1.0,
                asset=str(resp.url),
                module="headers",
                description="Content-Security-Policy includes 'unsafe-eval', allowing dynamic code execution.",
                remediation="Remove 'unsafe-eval' from CSP.",
                tags=["csp", "xss", "misconfiguration"],
            ))
        if "*" in csp_lower.split():
            ctx.add_finding(Finding(
                id="csp-wildcard",
                title="CSP uses wildcard source",
                severity=Severity.MEDIUM,
                confidence=0.9,
                asset=str(resp.url),
                module="headers",
                description="Content-Security-Policy uses wildcard (*) in source directives.",
                remediation="Replace wildcards with specific trusted origins.",
                tags=["csp", "misconfiguration"],
            ))
        if "default-src" not in csp_lower:
            ctx.add_finding(Finding(
                id="csp-no-default-src",
                title="CSP missing default-src directive",
                severity=Severity.LOW,
                confidence=0.9,
                asset=str(resp.url),
                module="headers",
                description="Content-Security-Policy does not include a default-src fallback.",
                remediation="Add a default-src directive to CSP.",
                tags=["csp", "misconfiguration"],
            ))