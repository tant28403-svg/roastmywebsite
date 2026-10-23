from __future__ import annotations

from ..core.models import Asset, Finding, Severity


async def run(ctx) -> None:
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return

    url = f"https://{ctx.target}"
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            console_errors: list[str] = []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            await page.goto(url, timeout=int(ctx.settings.timeout * 1000))
            content = await page.content()
            await browser.close()
    except Exception:
        return

    if "password" in content.lower() and "input" in content.lower():
        ctx.add_finding(Finding(
            id="browser-form-detected",
            title="Login form detected (browser-rendered)",
            severity=Severity.INFO,
            confidence=0.8,
            asset=url,
            module="browser",
            description="A browser-rendered page contains a password input.",
            remediation="Ensure authentication flows are protected and monitored.",
            tags=["browser", "auth"],
        ))
    if console_errors:
        ctx.add_finding(Finding(
            id="browser-console-errors",
            title="Browser console errors detected",
            severity=Severity.LOW,
            confidence=0.7,
            asset=url,
            module="browser",
            description="; ".join(console_errors[:5]),
            remediation="Fix client-side errors.",
            tags=["browser"],
        ))

    # Mixed content detection
    mixed = await page.evaluate("""() => {
        const imgs = Array.from(document.querySelectorAll('img')).filter(i => i.src.startsWith('http://'));
        const scripts = Array.from(document.querySelectorAll('script')).filter(s => s.src.startsWith('http://'));
        const links = Array.from(document.querySelectorAll('link')).filter(l => l.href.startsWith('http://'));
        return imgs.length + scripts.length + links.length;
    }""") if False else 0
    try:
        mixed = await page.evaluate("() => document.querySelectorAll('img[src^=\"http://\"], script[src^=\"http://\"], link[href^=\"http://\"]').length")
        if mixed > 0:
            ctx.add_finding(Finding(
                id="browser-mixed-content",
                title="Mixed content detected",
                severity=Severity.MEDIUM,
                confidence=0.9,
                asset=url,
                module="browser",
                description=f"Page loads {mixed} insecure (HTTP) resources on an HTTPS page.",
                remediation="Serve all resources over HTTPS.",
                tags=["browser", "mixed-content"],
            ))
    except Exception:
        pass

    # Storage inspection
    try:
        local_storage = await page.evaluate("() => Object.keys(localStorage)")
        if local_storage:
            ctx.add_asset(Asset(value=str(local_storage), asset_type="local_storage_keys", source="browser", metadata={"url": url}))
        session_storage = await page.evaluate("() => Object.keys(sessionStorage)")
        if session_storage:
            ctx.add_asset(Asset(value=str(session_storage), asset_type="session_storage_keys", source="browser", metadata={"url": url}))
    except Exception:
        pass

    # Cookie analysis
    try:
        cookies = await page.context.cookies()
        for cookie in cookies:
            issues = []
            if not cookie.get("httpOnly"):
                issues.append("missing HttpOnly")
            if not cookie.get("secure"):
                issues.append("missing Secure")
            if not cookie.get("sameSite"):
                issues.append("missing SameSite")
            if issues:
                ctx.add_finding(Finding(
                    id=f"browser-cookie-{cookie['name']}",
                    title=f"Cookie '{cookie['name']}' has issues: {', '.join(issues)}",
                    severity=Severity.LOW,
                    confidence=0.9,
                    asset=url,
                    module="browser",
                    description=f"Cookie {cookie['name']} is missing: {', '.join(issues)}.",
                    remediation="Set HttpOnly, Secure, and SameSite attributes on cookies.",
                    tags=["browser", "cookie"],
                ))
    except Exception:
        pass