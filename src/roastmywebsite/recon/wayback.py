from __future__ import annotations

from ..core.models import Asset


async def run(ctx) -> None:
    host = ctx.target
    if not ctx.can_request():
        return
    ctx.increment()
    url = f"http://web.archive.org/cdx/search/cdx?url={host}/*&output=text&fl=original&collapse=urlkey&limit=200"
    resp = await ctx.http.get(url, timeout=ctx.settings.timeout)
    if not resp.ok:
        return
    seen = set()
    params_found = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            ctx.add_asset(Asset(value=line, asset_type="wayback_url", source="wayback"))
            # Extract parameters from archived URLs
            from urllib.parse import parse_qs, urlparse
            try:
                parsed = urlparse(line)
                if parsed.query:
                    for key in parse_qs(parsed.query):
                        if key not in params_found:
                            params_found.add(key)
                            ctx.add_asset(Asset(value=key, asset_type="wayback_param", source="wayback", metadata={"url": line}))
            except Exception:
                pass