from __future__ import annotations

from ..core.models import Finding, Severity


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