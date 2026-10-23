from __future__ import annotations

import json

from ..core.models import Asset, Finding, Severity

SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
    "/swagger-ui.html", "/swagger-ui/", "/redoc", "/docs", "/api/swagger.json",
    "/api/openapi.json", "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/api/v3/swagger.json", "/swagger/v2/swagger.json", "/openapi.yaml",
    "/api/openapi.yaml", "/swagger.yaml", "/api-docs.json", "/api-docs.yaml",
]

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
    "/gql", "/query", "/rpc", "/soap", "/ws", "/websocket",
]

COMMON_API_ENDPOINTS = [
    "/api/users", "/api/user", "/api/admin", "/api/login", "/api/auth",
    "/api/register", "/api/token", "/api/health", "/api/status",
    "/api/config", "/api/settings", "/api/version", "/api/info",
]


async def run(ctx) -> None:
    # Check spec paths
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
                # Extract version
                info = data.get("info", {})
                version = info.get("version")
                if version:
                    ctx.add_asset(Asset(value=version, asset_type="api_version", source="api"))
            except Exception:
                pass

    # Check common API base paths
    for path in API_PATHS:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
        if resp.status_code in (200, 301, 302, 401, 403):
            ctx.add_asset(Asset(value=f"https://{ctx.target}{path}", asset_type="api_base", source="api", metadata={"status": resp.status_code}))

    # Check common API endpoints
    for path in COMMON_API_ENDPOINTS:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
        if resp.status_code in (200, 301, 302, 401, 403):
            ctx.add_asset(Asset(value=f"https://{ctx.target}{path}", asset_type="api_endpoint", source="api", metadata={"status": resp.status_code}))

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
            # Extract types from introspection
            try:
                data = json.loads(resp.text)
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                for t in types[:50]:
                    name = t.get("name", "")
                    if name and not name.startswith("__"):
                        ctx.add_asset(Asset(value=name, asset_type="graphql_type", source="api"))
            except Exception:
                pass

    # CORS check on API
    if ctx.can_request():
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}/api", headers={"Origin": "https://evil.com"}, timeout=ctx.settings.timeout)
        cors = resp.headers.get("access-control-allow-origin", "")
        if cors == "*" or "evil.com" in cors:
            ctx.add_finding(Finding(
                id="api-cors-misconfig",
                title="API CORS misconfiguration",
                severity=Severity.MEDIUM,
                confidence=0.9,
                asset=f"https://{ctx.target}/api",
                module="api",
                description=f"API allows cross-origin requests from arbitrary origins: {cors}",
                remediation="Restrict CORS to trusted origins.",
                tags=["api", "cors"],
            ))