from __future__ import annotations

import asyncio

from ..core.models import Finding, Severity

DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("root", "root"), ("test", "test")]


async def run(ctx) -> None:
    if not getattr(ctx.settings, "aggressive", False):
        return
    endpoints = ["/login", "/admin", "/wp-login.php", "/administrator"]

    async def _check_endpoint(endpoint: str) -> None:
        # Baseline with wrong credentials to know what a failed login looks like.
        baseline_body = ""
        baseline_status = 0
        if ctx.can_request():
            ctx.increment()
            baseline_resp = await ctx.http.post(
                f"https://{ctx.target}{endpoint}",
                data={"username": "rmw-nonexistent-user", "password": "rmw-wrong-pass-12345", "user": "rmw-nonexistent-user", "pass": "rmw-wrong-pass-12345"},
                timeout=ctx.settings.timeout,
            )
            baseline_body = (baseline_resp.text or "").lower()
            baseline_status = baseline_resp.status_code
        for user, password in DEFAULT_CREDS:
            if not ctx.can_request():
                return
            ctx.increment()
            resp = await ctx.http.post(f"https://{ctx.target}{endpoint}", data={"username": user, "password": password, "user": user, "pass": password}, timeout=ctx.settings.timeout)
            body = (resp.text or "").lower()
            success = False
            if (
                (resp.status_code in (302, 303) and baseline_status not in (302, 303))
                or ("dashboard" in body and "dashboard" not in baseline_body)
                or ("welcome" in body and "welcome" not in baseline_body)
            ):
                success = True
            if success:
                ctx.add_finding(Finding(
                    id=f"default-creds-{endpoint.strip('/')}",
                    title=f"Potential default credentials on {endpoint}",
                    severity=Severity.CRITICAL,
                    confidence=0.7,
                    asset=f"https://{ctx.target}{endpoint}",
                    module="auth",
                    description=f"Default credentials {user}:{password} may have succeeded.",
                    remediation="Change default credentials immediately.",
                    tags=["auth", "default-creds"],
                ))
                return

    tasks = [_check_endpoint(ep) for ep in endpoints]
    await asyncio.gather(*tasks, return_exceptions=True)