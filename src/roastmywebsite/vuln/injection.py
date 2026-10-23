from __future__ import annotations

import asyncio

from ..core.models import Finding, Severity

ERROR_SIGNATURES = [
    "sql syntax", "mysql", "postgres", "sqlite", "ora-", "unclosed quotation mark",
    "quoted string not properly terminated", "odbc", "jdbc", "syntax error",
]


async def _probe_param(ctx, base: str, param: str) -> None:
    payloads = ["'", "\"", "1'", "1\""]
    for payload in payloads:
        if not ctx.can_request():
            return
        ctx.increment()
        baseline_resp = await ctx.http.get(base, params={param: "1"}, timeout=ctx.settings.timeout)
        baseline_body = (baseline_resp.text or "").lower()
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
        body = (resp.text or "").lower()
        new_errors = [sig for sig in ERROR_SIGNATURES if sig in body and sig not in baseline_body]
        if new_errors:
            ctx.add_finding(Finding(
                id=f"sqli-error-{param}",
                title=f"Potential SQL injection via '{param}' parameter",
                severity=Severity.HIGH,
                confidence=0.7,
                asset=f"{base}?{param}={payload}",
                module="injection",
                description=f"SQL error signature ({new_errors[0]}) detected in response.",
                remediation="Use parameterized queries and input validation.",
                tags=["sqli", "injection"],
            ))
            return


async def run(ctx) -> None:
    params = ["id", "q", "search", "page", "user"]
    base = f"https://{ctx.target}"
    tasks = [_probe_param(ctx, base, param) for param in params]
    await asyncio.gather(*tasks, return_exceptions=True)