from __future__ import annotations

import asyncio

from ..core.models import Finding, Severity


async def run(ctx) -> None:
    # Lightweight IDOR probe: fetch sequential numeric object paths.
    paths = ["/api/users/1", "/api/users/2", "/user/1", "/user/2", "/account/1", "/account/2"]

    async def _fetch(path: str):
        if not ctx.can_request():
            return path, None
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
        return path, resp

    results = await asyncio.gather(*[_fetch(p) for p in paths], return_exceptions=True)
    responses = {}
    for r in results:
        if isinstance(r, Exception):
            continue
        path, resp = r
        if resp is not None:
            responses[path] = resp

    # Baseline: fetch a known-nonexistent path to detect soft 404s.
    baseline_status = 0
    baseline_len = 0
    if ctx.can_request():
        ctx.increment()
        baseline_resp = await ctx.http.get(f"https://{ctx.target}/rmw-nonexistent-probe-12345", timeout=ctx.settings.timeout)
        baseline_status = baseline_resp.status_code
        baseline_len = len(baseline_resp.text or "")

    # Only flag endpoints whose response differs from the soft-404 baseline.
    ok = []
    for p, r in responses.items():
        if r.status_code == 200:
            body_len = len(r.text or "")
            if r.status_code == baseline_status and abs(body_len - baseline_len) < 50:
                continue
            ok.append(p)

    if len(ok) >= 2:
        ctx.add_finding(Finding(
            id="idor-candidate",
            title="Possible IDOR: sequential object endpoints accessible",
            severity=Severity.MEDIUM,
            confidence=0.5,
            asset=ctx.target,
            module="idor",
            description=f"Accessible endpoints: {', '.join(ok)}",
            remediation="Enforce object-level authorization checks.",
            tags=["idor", "authz"],
        ))