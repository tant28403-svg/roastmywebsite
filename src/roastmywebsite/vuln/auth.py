from __future__ import annotations

import asyncio
import base64
import json

from ..core.models import Finding, Severity

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("test", "test"), ("test", "password"), ("guest", "guest"),
    ("user", "user"), ("user", "password"), ("demo", "demo"),
    ("administrator", "administrator"), ("administrator", "password"),
    ("sa", "sa"), ("sa", "password"), ("postgres", "postgres"),
    ("mysql", "mysql"), ("oracle", "oracle"),
    # CMS defaults
    ("admin", "admin"), ("wp", "wp"), ("drupal", "drupal"),
    # Device defaults
    ("admin", "1234"), ("admin", "12345"), ("admin", "password123"),
]

LOGIN_ENDPOINTS = [
    "/login", "/admin", "/wp-login.php", "/administrator", "/signin",
    "/auth", "/auth/login", "/user/login", "/account/login",
    "/api/login", "/api/auth", "/api/signin", "/api/token",
]


async def _analyze_jwt(ctx, token: str) -> None:
    """Analyze a JWT token for weaknesses."""
    parts = token.split(".")
    if len(parts) != 3:
        return
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    except Exception:
        return

    alg = header.get("alg", "")
    if alg.lower() == "none":
        ctx.add_finding(Finding(
            id="jwt-none-alg",
            title="JWT uses 'none' algorithm",
            severity=Severity.CRITICAL,
            confidence=1.0,
            asset=ctx.target,
            module="auth",
            description="JWT token uses the 'none' algorithm, allowing signature bypass.",
            remediation="Reject tokens with 'none' algorithm. Use RS256 or HS256.",
            tags=["jwt", "auth", "critical"],
        ))
    if alg.startswith("HS"):
        ctx.add_finding(Finding(
            id="jwt-symmetric",
            title="JWT uses symmetric algorithm (potential weak secret)",
            severity=Severity.MEDIUM,
            confidence=0.6,
            asset=ctx.target,
            module="auth",
            description=f"JWT uses {alg}. Ensure the secret is strong and not guessable.",
            remediation="Use RS256 (asymmetric) instead of HS256. Use a strong secret.",
            tags=["jwt", "auth"],
        ))

    # Check for sensitive data in payload
    sensitive_keys = ["password", "secret", "api_key", "apikey", "token", "credit_card", "ssn"]
    for key in sensitive_keys:
        if key in str(payload).lower():
            ctx.add_finding(Finding(
                id="jwt-sensitive-data",
                title="JWT contains sensitive data",
                severity=Severity.HIGH,
                confidence=0.8,
                asset=ctx.target,
                module="auth",
                description=f"JWT payload contains sensitive field: {key}",
                remediation="Remove sensitive data from JWT payload.",
                tags=["jwt", "auth", "data-exposure"],
            ))
            break

    # Check expiry
    exp = payload.get("exp")
    if exp:
        import time
        if exp < time.time():
            ctx.add_finding(Finding(
                id="jwt-expired",
                title="JWT token is expired",
                severity=Severity.LOW,
                confidence=1.0,
                asset=ctx.target,
                module="auth",
                description="The JWT token has expired.",
                remediation="Ensure proper token refresh mechanism.",
                tags=["jwt", "auth"],
            ))


async def run(ctx) -> None:
    if not getattr(ctx.settings, "aggressive", False):
        return

    async def _check_endpoint(endpoint: str) -> None:
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
                or ("logged in" in body and "logged in" not in baseline_body)
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

    # Check endpoints in parallel
    tasks = [_check_endpoint(ep) for ep in LOGIN_ENDPOINTS]
    await asyncio.gather(*tasks, return_exceptions=True)

    # JWT analysis: check if any response contains a JWT
    if ctx.can_request():
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}", timeout=ctx.settings.timeout)
        import re
        jwt_pattern = r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
        for match in re.finditer(jwt_pattern, resp.text or ""):
            await _analyze_jwt(ctx, match.group(0))