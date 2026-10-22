from __future__ import annotations

from ..core.models import Finding, Severity

ERROR_SIGNATURES = [
    "sql syntax", "mysql", "postgres", "sqlite", "ora-", "unclosed quotation mark",
    "quoted string not properly terminated", "odbc", "jdbc", "syntax error",
]


async def run(ctx) -> None:
    # Probe common parameters on the root URL with harmless SQLi markers.
    params = ["id", "q", "search", "page", "user"]
    payloads = ["'", "\"", "1'", "1\""]
    base = f"https://{ctx.target}"
    for param in params:
        for payload in payloads:
            if not ctx.can_request():
                return
            ctx.increment()
            resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
            body = (resp.text or "").lower()
            if any(sig in body for sig in ERROR_SIGNATURES):
                ctx.add_finding(Finding(
                    id=f"sqli-error-{param}",
                    title=f"Potential SQL injection via '{param}' parameter",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    asset=f"{base}?{param}={payload}",
                    module="injection",
                    description="Database error signature detected in response.",
                    remediation="Use parameterized queries and input validation.",
                    tags=["sqli", "injection"],
                ))
                break