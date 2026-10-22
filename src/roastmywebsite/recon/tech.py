from __future__ import annotations

from ..core.models import Asset

SIGNATURES = {
    "wordpress": ["wp-content", "wp-includes", "wordpress"],
    "drupal": ["drupal", "sites/all"],
    "joomla": ["joomla", "/components/com_"],
    "react": ["react", "__NEXT_DATA__", "react-dom"],
    "vue": ["vue.js", "vue.min.js", "__VUE__"],
    "angular": ["angular", "ng-version"],
    "jquery": ["jquery"],
    "bootstrap": ["bootstrap"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["iis", "asp.net"],
    "cloudflare": ["cloudflare", "cf-ray"],
    "php": ["php", "x-powered-by: php"],
}


async def run(ctx) -> None:
    if not ctx.can_request():
        return
    ctx.increment()
    resp = await ctx.http.get(f"https://{ctx.target}", timeout=ctx.settings.timeout)
    if not resp.ok:
        ctx.increment()
        resp = await ctx.http.get(f"http://{ctx.target}", timeout=ctx.settings.timeout)
    if not resp.ok and resp.error:
        return
    haystack = (resp.text + "\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())).lower()
    detected = []
    for name, sigs in SIGNATURES.items():
        if any(sig.lower() in haystack for sig in sigs):
            detected.append(name)
            ctx.add_asset(Asset(value=name, asset_type="technology", source="tech", metadata={"target": ctx.target}))
    # Server header
    server = resp.headers.get("server") or resp.headers.get("Server")
    if server:
        ctx.add_asset(Asset(value=server, asset_type="server", source="tech"))
    powered = resp.headers.get("x-powered-by") or resp.headers.get("X-Powered-By")
    if powered:
        ctx.add_asset(Asset(value=powered, asset_type="powered_by", source="tech"))