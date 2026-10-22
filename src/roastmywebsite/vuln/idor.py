from __future__ import annotations

from ..core.models import Finding, Severity


async def run(ctx) -> None:
    # Lightweight IDOR probe: fetch sequential numeric object paths.
    paths = ["/api/users/1", "/api/users/2", "/user/1", "/user/2", "/account/1", "/account/2"]
    responses = {}
    for path in paths:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
        responses[path] = resp
    # If multiple endpoints return 200 with similar sizes, flag for manual review.
    ok = [p for p, r in responses.items() if r.status_code == 200]
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