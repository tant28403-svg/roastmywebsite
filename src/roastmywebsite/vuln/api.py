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
    # Honeypot API endpoints
    "/api/debug/env", "/api/env", "/api/secrets", "/api/keys",
    "/api/debug", "/api/internal/config", "/api/v1/config",
    # Static config files
    "/config.js", "/api-config.json",
]

# HTTP methods to test on API endpoints
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

# Content-Types that indicate a real API response
API_CONTENT_TYPES = {
    "application/json",
    "application/xml",
    "application/hal+json",
    "application/vnd.api+json",
    "text/xml",
    "application/graphql",
    "application/ld+json",
    "application/x-yaml",
    "application/yaml",
}

# Content-Types that indicate SPA fallback (serving index.html)
SPA_FALLBACK_CONTENT_TYPES = {
    "text/html",
    "application/xhtml+xml",
}

# HTML indicators of SPA index.html fallback
SPA_INDICATORS = [
    "<!doctype html", "<html", "<head", "<body",
    "<div id=\"root\">", "<div id=\"app\">", "<div id=\"__next\">",
    "id=\"root\"", "id=\"app\"", "data-reactroot",
    "<script src=\"/", "webpack", "__next_data__",
    "react-dom", "vue.", "angular", "svelte",
]


def _is_spa_fallback(response) -> bool:
    """Return True if response appears to be SPA index.html fallback."""
    ct = (response.headers.get("content-type") or "").lower()
    if any(spa_ct in ct for spa_ct in SPA_FALLBACK_CONTENT_TYPES):
        body = (response.text or "")[:500].lower()
        return any(indicator in body for indicator in SPA_INDICATORS)
    return False


def _is_real_api(response) -> bool:
    """Return True if response looks like a real API."""
    ct = (response.headers.get("content-type") or "").lower()
    return any(api_ct in ct for api_ct in API_CONTENT_TYPES)


async def run(ctx) -> None:
    # Check spec paths
    for path in SPEC_PATHS:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
        if resp.status_code < 500:
            is_spa = _is_spa_fallback(resp)
            is_api = _is_real_api(resp)
            if is_api:
                # Real API spec - parse and extract endpoints
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
            elif is_spa:
                # SPA fallback - mark as such
                ctx.add_asset(Asset(value=f"https://{ctx.target}{path}", asset_type="spa_fallback", source="api", metadata={"status": resp.status_code}))
            else:
                # Other (404, 400, etc.)
                ctx.add_asset(Asset(value=f"https://{ctx.target}{path}", asset_type="http_endpoint", source="api", metadata={"status": resp.status_code}))

    # Check common API base paths
    for path in API_PATHS:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
        if resp.status_code < 500:
            is_spa = _is_spa_fallback(resp)
            is_api = _is_real_api(resp)
            if is_api or resp.status_code in (401, 403):
                asset_type = "api_base"
            elif is_spa:
                asset_type = "spa_fallback"
            else:
                asset_type = "http_endpoint"
            ctx.add_asset(Asset(value=f"https://{ctx.target}{path}", asset_type=asset_type, source="api", metadata={"status": resp.status_code}))

    # Check common API endpoints with multiple HTTP methods
    for path in COMMON_API_ENDPOINTS:
        for method in HTTP_METHODS:
            if not ctx.can_request():
                return
            ctx.increment()
            try:
                resp = await ctx.http.request(method, f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
                if resp.status_code >= 500:
                    continue
                is_spa = _is_spa_fallback(resp)
                is_api = _is_real_api(resp)
                if is_api or resp.status_code in (401, 403):
                    asset_type = "api_endpoint"
                elif is_spa:
                    asset_type = "spa_fallback"
                else:
                    asset_type = "http_endpoint"
                ctx.add_asset(Asset(
                    value=f"https://{ctx.target}{path}",
                    asset_type=asset_type,
                    source="api",
                    metadata={
                        "status": resp.status_code,
                        "method": method,
                        "content_type": resp.headers.get("content-type", ""),
                        "is_spa_fallback": is_spa,
                    }
                ))
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

    # API method testing: check if dangerous methods are allowed
    for path in ["/api", "/api/v1", "/api/users"]:
        if not ctx.can_request():
            break
        ctx.increment()
        resp = await ctx.http.request("OPTIONS", f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
        allow = resp.headers.get("allow", resp.headers.get("access-control-allow-methods", ""))
        if allow:
            dangerous = [m for m in ["PUT", "DELETE", "PATCH", "TRACE"] if m in allow.upper()]
            if dangerous:
                ctx.add_finding(Finding(
                    id=f"api-dangerous-methods-{path.strip('/').replace('/', '-')}",
                    title=f"Dangerous HTTP methods allowed on {path}",
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    asset=f"https://{ctx.target}{path}",
                    module="api",
                    description=f"Endpoint allows dangerous methods: {', '.join(dangerous)}. Allow header: {allow}",
                    remediation="Disable unnecessary HTTP methods on API endpoints.",
                    tags=["api", "methods"],
                ))