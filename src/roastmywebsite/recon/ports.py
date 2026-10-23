from __future__ import annotations

import asyncio

from ..core.models import Asset
from ..core.tools import run_tool, which

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 2181, 2375, 2376, 3000, 3306, 3389, 4443, 5000, 5432, 5601, 5900, 5984, 6379, 6443, 7001, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017, 50000]


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
    tool = getattr(ctx.settings, "ports_tool", "auto").lower()

    # Forced nmap
    if tool == "nmap":
        if not which("nmap"):
            return
        rc, out, _ = run_tool(["nmap", "-Pn", "-sV", "-sC", "-p", ",".join(map(str, COMMON_PORTS)), host], timeout=300)
        if rc == 0:
            for line in out.splitlines():
                if "/tcp" in line and "open" in line:
                    port = line.split("/")[0].strip()
                    if port.isdigit():
                        ctx.add_asset(Asset(value=f"{host}:{port}", asset_type="open_port", source="nmap", metadata={"port": int(port)}))
        return

    # Forced naabu
    if tool == "naabu":
        if not which("naabu"):
            return
        rc, out, _ = run_tool(["naabu", "-host", host, "-silent", "-p", ",".join(map(str, COMMON_PORTS))], timeout=300)
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if ":" in line:
                    _, port = line.rsplit(":", 1)
                    if port.isdigit():
                        ctx.add_asset(Asset(value=f"{host}:{port}", asset_type="open_port", source="naabu", metadata={"port": int(port)}))
        return

    # Auto mode: naabu → nmap → TCP connect
    if which("naabu"):
        rc, out, _ = run_tool(["naabu", "-host", host, "-silent", "-p", ",".join(map(str, COMMON_PORTS))], timeout=300)
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if ":" in line:
                    _, port = line.rsplit(":", 1)
                    if port.isdigit():
                        ctx.add_asset(Asset(value=f"{host}:{port}", asset_type="open_port", source="naabu", metadata={"port": int(port)}))
            return

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
                # Try to grab banner
                banner = ""
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.0)
                    try:
                        data = await asyncio.wait_for(reader.read(256), timeout=2.0)
                        banner = data.decode("utf-8", "ignore").strip()[:200]
                    except Exception:
                        pass
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                ctx.add_asset(Asset(value=f"{host}:{port}", asset_type="open_port", source="tcp-connect", metadata={"port": port, "banner": banner}))

    await asyncio.gather(*(check(p) for p in COMMON_PORTS))