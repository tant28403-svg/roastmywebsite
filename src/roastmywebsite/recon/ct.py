from __future__ import annotations

import json

from ..core.models import Asset


async def run(ctx) -> None:
    root = ctx.target
    if not ctx.can_request():
        return
    ctx.increment()
    resp = await ctx.http.get(f"https://crt.sh/?q=%25.{root}&output=json", timeout=ctx.settings.timeout)
    if not resp.ok:
        return
    try:
        data = json.loads(resp.text)
    except Exception:
        return
    seen = set()
    for entry in data:
        for line in entry.get("name_value", "").splitlines():
            line = line.strip().lower()
            if line and "*" not in line and line not in seen:
                seen.add(line)
                ctx.add_asset(Asset(value=line, asset_type="ct_subdomain", source="ct"))