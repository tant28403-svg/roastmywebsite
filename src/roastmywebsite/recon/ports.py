from __future__ import annotations

import asyncio

from ..core.models import Asset
from ..core.tools import run_tool, which

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]


async def _tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def run(ctx) -> None:
    host = ctx.target
    # Prefer naabu
    if which("naabu"):
        rc, out, _ = run_tool(["naabu", "-host", host, "-silent", "-p", ",".join(map(str, COMMON_PORTS))], timeout=120)
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if ":" in line:
                    _, port = line.rsplit(":", 1)
                    if port.isdigit():
                        ctx.add_asset(Asset(value=f"{host}:{port}", asset_type="open_port", source="naabu", metadata={"port": int(port)}))
            return

    # Prefer nmap
    if which("nmap"):
        rc, out, _ = run_tool(["nmap", "-Pn", "-p", ",".join(map(str, COMMON_PORTS)), host], timeout=300)
        if rc == 0:
            for line in out.splitlines():
                if "/tcp" in line and "open" in line:
                    port = line.split("/")[0].strip()
                    if port.isdigit():
                        ctx.add_asset(Asset(value=f"{host}:{port}", asset_type="open_port", source="nmap", metadata={"port": int(port)}))
            return

    # Fallback: async connect
    sem = asyncio.Semaphore(ctx.settings.concurrency)

    async def check(port: int) -> None:
        if not ctx.can_request():
            return
        ctx.increment()
        async with sem:
            if await _tcp_connect(host, port, min(ctx.settings.timeout, 3.0)):
                ctx.add_asset(Asset(value=f"{host}:{port}", asset_type="open_port", source="tcp-connect", metadata={"port": port}))

    await asyncio.gather(*(check(p) for p in COMMON_PORTS))