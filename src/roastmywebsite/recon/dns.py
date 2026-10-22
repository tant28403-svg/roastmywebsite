from __future__ import annotations

import asyncio
import socket

import dns.resolver

from ..core.models import Asset


async def run(ctx) -> None:
    host = ctx.target
    resolver = dns.resolver.Resolver()
    resolver.timeout = ctx.settings.timeout
    resolver.lifetime = ctx.settings.timeout

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]
    for rtype in record_types:
        if not ctx.can_request():
            return
        ctx.increment()
        try:
            answers = await asyncio.to_thread(resolver.resolve, host, rtype)
        except Exception:
            continue
        for answer in answers:
            value = str(answer).rstrip(".")
            ctx.add_asset(Asset(value=value, asset_type=f"dns_{rtype.lower()}", source="dns", metadata={"host": host}))
        if rtype == "TXT":
            for answer in answers:
                text = str(answer)
                if "v=spf1" in text.lower():
                    ctx.add_asset(Asset(value=text, asset_type="spf", source="dns"))

    # Reverse DNS for A records
    try:
        infos = await asyncio.to_thread(socket.gethostbyname_ex, host)
        for ip in infos[2]:
            try:
                ptr = await asyncio.to_thread(socket.gethostbyaddr, ip)
                ctx.add_asset(Asset(value=ptr[0], asset_type="ptr", source="dns", metadata={"ip": ip}))
            except Exception:
                pass
    except Exception:
        pass