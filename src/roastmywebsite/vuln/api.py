from __future__ import annotations

import json

from ..core.models import Asset, Finding, Severity

SPEC_PATHS = ["/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json"]


async def run(ctx) -> None:
    for path in SPEC_PATHS:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
        if resp.status_code == 200:
            ctx.add_asset(Asset(value=f"https://{ctx.target}{path}", asset_type="api_spec", source="api"))
            try:
                data = json.loads(resp.text)
                paths = data.get("paths", {})
                for p in list(paths.keys())[:50]:
                    ctx.add_asset(Asset(value=p, asset_type="api_endpoint", source="api", metadata={"spec": path}))
            except Exception:
                pass
    # GraphQL introspection
    if ctx.can_request():
        ctx.increment()
        resp = await ctx.http.post(f"https://{ctx.target}/graphql", json={"query": "{__schema{types{name}}}"}, timeout=ctx.settings.timeout)
        if resp.status_code == 200 and "__schema" in (resp.text or ""):
            ctx.add_finding(Finding(
                id="graphql-introspection",
                title="GraphQL introspection enabled",
                severity=Severity.LOW,
                confidence=1.0,
                asset=f"https://{ctx.target}/graphql",
                module="api",
                description="GraphQL introspection is enabled in production.",
                remediation="Disable introspection in production.",
                tags=["api", "graphql"],
            ))