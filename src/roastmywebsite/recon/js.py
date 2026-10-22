from __future__ import annotations

from ..core.models import Asset

ENDPOINT_PATTERNS = [
    r"""["'](\/[a-zA-Z0-9_\-\/\.]+)["']""",
    r"""fetch\(["']([^"']+)["']""",
    r"""axios\.[a-z]+\(["']([^"']+)["']""",
]
SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"sk_live_[0-9a-zA-Z]{24}",
    r"ghp_[0-9a-zA-Z]{36}",
]


async def run(ctx) -> None:
    # Reuse crawled JS URLs by fetching common script paths is expensive; scan main page scripts.
    if not ctx.can_request():
        return
    ctx.increment()
    resp = await ctx.http.get(f"https://{ctx.target}", timeout=ctx.settings.timeout)
    if not resp.ok:
        return
    import re as _re
    scripts = _re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", resp.text, _re.IGNORECASE)
    seen: set[str] = set()
    for src in scripts[:20]:
        if not ctx.can_request():
            return
        url = src if src.startswith("http") else f"https://{ctx.target}/{src.lstrip('/')}"
        if url in seen:
            continue
        seen.add(url)
        ctx.increment()
        r = await ctx.http.get(url, timeout=ctx.settings.timeout)
        if not r.ok:
            continue
        for pat in ENDPOINT_PATTERNS:
            for match in _re.findall(pat, r.text):
                endpoint = match if isinstance(match, str) else match[0]
                if endpoint.startswith("/") and len(endpoint) < 120:
                    ctx.add_asset(Asset(value=endpoint, asset_type="js_endpoint", source="js", metadata={"script": url}))
        for pat in SECRET_PATTERNS:
            for match in _re.findall(pat, r.text):
                ctx.add_asset(Asset(value=match, asset_type="secret", source="js", metadata={"script": url}))