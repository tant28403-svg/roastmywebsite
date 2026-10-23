from __future__ import annotations

import json

from ..core.models import Asset


async def run(ctx) -> None:
    root = ctx.target
    # crt.sh
    if ctx.can_request():
        ctx.increment()
        resp = await ctx.http.get(f"https://crt.sh/?q=%25.{root}&output=json", timeout=ctx.settings.timeout)
        if resp.ok:
            try:
                data = json.loads(resp.text)
            except Exception:
                data = []
            seen = set()
            for entry in data:
                for line in entry.get("name_value", "").splitlines():
                    line = line.strip().lower()
                    if line and "*" not in line and line not in seen:
                        seen.add(line)
                        ctx.add_asset(Asset(value=line, asset_type="ct_subdomain", source="ct"))
                # Extract SANs
                for entry in data:
                    name = entry.get("name_value", "")
                    if name:
                        for san in name.splitlines():
                            san = san.strip().lower()
                            if san and san not in seen:
                                seen.add(san)
                                ctx.add_asset(Asset(value=san, asset_type="ct_san", source="ct"))

    # Google CT (via crt.sh is primary, but we can also check certspotter)
    if ctx.can_request():
        ctx.increment()
        resp = await ctx.http.get(f"https://api.certspotter.com/v1/issuances?domain={root}&include_subdomains=true&expand=dns_names", timeout=ctx.settings.timeout)
        if resp.ok:
            try:
                data = json.loads(resp.text)
            except Exception:
                data = []
            seen = set()
            for entry in data:
                for name in entry.get("dns_names", []):
                    name = name.strip().lower()
                    if name and "*" not in name and name not in seen:
                        seen.add(name)
                        ctx.add_asset(Asset(value=name, asset_type="ct_subdomain", source="certspotter"))