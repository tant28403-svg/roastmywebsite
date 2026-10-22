from __future__ import annotations

from ..core.models import Finding, Severity


async def run(ctx) -> None:
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return

    payload = '"><script>window.__rmw_xss=true</script>'
    marker = "rmwXSS123"
    params = ["q", "search", "name", "redirect", "next", "return", "msg"]
    for param in params:
        if not ctx.can_request():
            return
        ctx.increment()
        url = f"https://{ctx.target}?{param}={payload}"
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(url, timeout=int(ctx.settings.timeout * 1000))
                content = await page.content()
                executed = False
                try:
                    executed = await page.evaluate("() => window.__rmw_xss === true")
                except Exception:
                    executed = False
                await browser.close()
        except Exception:
            continue
        if payload in content or marker in content:
            ctx.add_finding(Finding(
                id=f"dom-xss-reflected-{param}",
                title=f"Potential DOM XSS via '{param}' parameter",
                severity=Severity.MEDIUM,
                confidence=0.7,
                asset=url,
                module="dom_xss",
                description="Payload reflected in browser-rendered DOM.",
                remediation="Apply context-aware output encoding and CSP.",
                tags=["xss", "dom"],
            ))
        if executed:
            ctx.add_finding(Finding(
                id=f"dom-xss-executed-{param}",
                title=f"DOM XSS executed via '{param}' parameter",
                severity=Severity.HIGH,
                confidence=0.9,
                asset=url,
                module="dom_xss",
                description="Injected script executed in the browser.",
                remediation="Fix output encoding and avoid unsafe DOM sinks.",
                tags=["xss", "dom", "execution"],
            ))