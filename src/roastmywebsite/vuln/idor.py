from __future__ import annotations

import asyncio

from ..core.models import Finding, Severity

# Common IDOR endpoint patterns
IDOR_PATHS = [
    "/api/users/1", "/api/users/2", "/api/v1/users/1", "/api/v1/users/2",
    "/user/1", "/user/2", "/users/1", "/users/2",
    "/account/1", "/account/2", "/accounts/1", "/accounts/2",
    "/profile/1", "/profile/2", "/order/1", "/order/2",
    "/document/1", "/document/2", "/file/1", "/file/2",
]

# Common IDOR parameters to test
IDOR_PARAMS = [
    "id", "user_id", "account_id", "uid", "userid", "user", "account",
    "profile_id", "order_id", "doc_id",
]

# Values to test for parameter tampering
IDOR_VALUES = ["1", "2", "0", "999", "admin", "test"]


async def run(ctx) -> None:
    base = f"https://{ctx.target}"

    # Phase 1: Sequential path probing
    async def _fetch(path: str):
        if not ctx.can_request():
            return path, None
        ctx.increment()
        resp = await ctx.http.get(f"{base}{path}", timeout=ctx.settings.timeout)
        return path, resp

    results = await asyncio.gather(*[_fetch(p) for p in IDOR_PATHS], return_exceptions=True)
    responses = {}
    for r in results:
        if isinstance(r, Exception):
            continue
        path, resp = r
        if resp is not None:
            responses[path] = resp

    # Baseline: fetch a known-nonexistent path to detect soft 404s
    baseline_status = 0
    baseline_len = 0
    if ctx.can_request():
        ctx.increment()
        baseline_resp = await ctx.http.get(f"{base}/rmw-nonexistent-probe-12345", timeout=ctx.settings.timeout)
        baseline_status = baseline_resp.status_code
        baseline_len = len(baseline_resp.text or "")

    # Only flag endpoints whose response differs from the soft-404 baseline
    ok_paths = []
    for p, r in responses.items():
        if r.status_code == 200:
            body_len = len(r.text or "")
            if r.status_code == baseline_status and abs(body_len - baseline_len) < 50:
                continue
            ok_paths.append(p)

    if len(ok_paths) >= 2:
        ctx.add_finding(Finding(
            id="idor-path-candidate",
            title="Possible IDOR: sequential object endpoints accessible",
            severity=Severity.MEDIUM,
            confidence=0.5,
            asset=ctx.target,
            module="idor",
            description=f"Accessible endpoints: {', '.join(ok_paths[:10])}",
            remediation="Enforce object-level authorization checks.",
            tags=["idor", "authz"],
        ))

    # Phase 2: Parameter tampering
    for param in IDOR_PARAMS:
        if not ctx.can_request():
            break
        # Baseline with a normal value
        ctx.increment()
        baseline_resp = await ctx.http.get(f"{base}/", params={param: "1"}, timeout=ctx.settings.timeout)
        baseline_body = baseline_resp.text or ""
        baseline_status = baseline_resp.status_code
        baseline_len = len(baseline_body)

        different_responses = 0
        for val in IDOR_VALUES[1:]:  # Skip "1" since it's the baseline
            if not ctx.can_request():
                break
            ctx.increment()
            resp = await ctx.http.get(f"{base}/", params={param: val}, timeout=ctx.settings.timeout)
            if resp.status_code == 200:
                body_len = len(resp.text or "")
                if not (resp.status_code == baseline_status and abs(body_len - baseline_len) < 50):
                    different_responses += 1

        if different_responses >= 2:
            ctx.add_finding(Finding(
                id=f"idor-param-{param}",
                title=f"Potential IDOR via '{param}' parameter",
                severity=Severity.MEDIUM,
                confidence=0.6,
                asset=f"{base}/?{param}=1",
                module="idor",
                description=f"Parameter '{param}' returns different responses for different values, suggesting IDOR.",
                remediation="Enforce object-level authorization checks on all parameters.",
                tags=["idor", "authz", "parameter-tampering"],
            ))