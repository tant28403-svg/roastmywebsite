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


async def _resolve(name: str, timeout: float = 5.0) -> bool:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        await asyncio.to_thread(resolver.resolve, name, "A")
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
            if await _resolve(name, ctx.settings.timeout):
                found.add(name)

    await asyncio.gather(*(check(s) for s in COMMON_SUBS))

    # Permutation-based discovery: try common prefixes/suffixes on found subdomains
    permutations = ["dev", "staging", "test", "prod", "api", "v2", "v1", "new", "old", "backup"]
    perm_targets = []
    for sub in list(found)[:10]:  # Limit to first 10 found
        for perm in permutations:
            perm_targets.append(f"{perm}.{sub}")
            perm_targets.append(f"{sub}.{perm}")
    if perm_targets:
        sem2 = asyncio.Semaphore(ctx.settings.concurrency)

        async def check_perm(name: str) -> None:
            if not ctx.can_request():
                return
            ctx.increment()
            async with sem2:
                if await _resolve(name, ctx.settings.timeout):
                    found.add(name)
                    ctx.add_asset(Asset(value=name, asset_type="subdomain", source="permutation"))

        await asyncio.gather(*(check_perm(t) for t in perm_targets[:50]))

    tool = getattr(ctx.settings, "subdomain_tool", "auto").lower()

    from ..core.tools import run_tool, which

    # Forced or auto: subfinder
    if tool in ("auto", "subfinder", "both") and which("subfinder"):
        rc, out, _ = run_tool(["subfinder", "-d", root, "-silent"], timeout=300)
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if line:
                    found.add(line)
                    ctx.add_asset(Asset(value=line, asset_type="subdomain", source="subfinder"))

    # Forced or auto: amass
    if tool in ("auto", "amass", "both") and which("amass"):
        rc, out, _ = run_tool(["amass", "enum", "-d", root, "-silent"], timeout=300)
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if line:
                    found.add(line)
                    ctx.add_asset(Asset(value=line, asset_type="subdomain", source="amass"))

    for sub in sorted(found):
        if sub == root:
            continue
        ctx.add_asset(Asset(value=sub, asset_type="subdomain", source="subdomains"))