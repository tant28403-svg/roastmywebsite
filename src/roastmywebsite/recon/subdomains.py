from __future__ import annotations

import asyncio
import json

import dns.resolver
import tldextract

from ..core.models import Asset

COMMON_SUBS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "blog", "shop",
    "portal", "vpn", "remote", "m", "app", "cdn", "static", "assets", "img", "images",
    "secure", "login", "auth", "dashboard", "panel", "beta", "alpha", "demo", "git",
    "jenkins", "jira", "confluence", "grafana", "kibana", "prometheus", "s3", "backup",
]


async def _resolve(name: str) -> bool:
    try:
        await asyncio.to_thread(dns.resolver.resolve, name, "A")
        return True
    except Exception:
        return False


async def run(ctx) -> None:
    domain = ctx.target
    ext = tldextract.extract(domain)
    root = ".".join(part for part in [ext.domain, ext.suffix] if part)
    found: set[str] = set()

    # Certificate Transparency via crt.sh
    if ctx.can_request():
        ctx.increment()
        url = f"https://crt.sh/?q=%25.{root}&output=json"
        resp = await ctx.http.get(url, timeout=ctx.settings.timeout)
        if resp.ok:
            try:
                data = json.loads(resp.text)
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.splitlines():
                        line = line.strip().lower()
                        if line and "*" not in line:
                            found.add(line)
            except Exception:
                pass

    # DNS brute force
    semaphore = asyncio.Semaphore(ctx.settings.concurrency)

    async def check(sub: str) -> None:
        if not ctx.can_request():
            return
        ctx.increment()
        name = f"{sub}.{root}"
        async with semaphore:
            if await _resolve(name):
                found.add(name)

    await asyncio.gather(*(check(s) for s in COMMON_SUBS))

    # Optional external subfinder
    from ..core.tools import run_tool, which

    if which("subfinder"):
        rc, out, _ = run_tool(["subfinder", "-d", root, "-silent"], timeout=120)
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if line:
                    found.add(line)

    for sub in sorted(found):
        if sub == root:
            continue
        ctx.add_asset(Asset(value=sub, asset_type="subdomain", source="subdomains"))