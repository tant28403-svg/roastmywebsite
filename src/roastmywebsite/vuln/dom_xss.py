from __future__ import annotations

from ..core.models import Finding, Severity


async def run(ctx) -> None:
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return

    payload = '"><script>window.__rmw_xss=true</script>'
    # DOM sinks to test
    params = ["q", "search", "name", "redirect", "next", "return", "msg", "callback", "cb", "jsonp", "cb", "handler", "cbk", "jsonpcallback", "cbfunc"]
    # Template injection payloads
    template_payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{constructor.constructor('alert(1)')()}}"]

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
        if payload in content:
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

    # Template injection testing
    for param in params[:5]:
        for tpl in template_payloads:
            if not ctx.can_request():
                return
            ctx.increment()
            url = f"https://{ctx.target}?{param}={tpl}"
            try:
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    page = await browser.new_page()
                    await page.goto(url, timeout=int(ctx.settings.timeout * 1000))
                    content = await page.content()
                    await browser.close()
            except Exception:
                continue
            # Check if template was evaluated (49 = 7*7)
            if "49" in content and tpl not in content:
                ctx.add_finding(Finding(
                    id=f"template-injection-{param}",
                    title=f"Potential template injection via '{param}' parameter",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    asset=url,
                    module="dom_xss",
                    description=f"Template expression {tpl} was evaluated to 49.",
                    remediation="Avoid rendering user input in templates. Use sandboxed template engines.",
                    tags=["ssti", "template-injection"],
                ))
                break