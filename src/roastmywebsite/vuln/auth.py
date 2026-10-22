from __future__ import annotations

from ..core.models import Finding, Severity

DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("root", "root"), ("test", "test")]


async def run(ctx) -> None:
    # Check common login endpoints for default credentials (only if user enables aggressive)
    if not getattr(ctx.settings, "aggressive", False):
        return
    endpoints = ["/login", "/admin", "/wp-login.php", "/administrator"]
    for endpoint in endpoints:
        for user, password in DEFAULT_CREDS:
            if not ctx.can_request():
                return
            ctx.increment()
            resp = await ctx.http.post(f"https://{ctx.target}{endpoint}", data={"username": user, "password": password, "user": user, "pass": password}, timeout=ctx.settings.timeout)
            body = (resp.text or "").lower()
            if resp.status_code in (302, 303) or "dashboard" in body or "welcome" in body:
                ctx.add_finding(Finding(
                    id=f"default-creds-{endpoint.strip('/')}",
                    title=f"Possible default credentials accepted at {endpoint}",
                    severity=Severity.CRITICAL,
                    confidence=0.6,
                    asset=f"https://{ctx.target}{endpoint}",
                    module="auth",
                    description=f"Tried {user}:{password}",
                    remediation="Change default credentials and enforce strong passwords.",
                    tags=["auth", "default-creds"],
                ))