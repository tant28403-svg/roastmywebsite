import asyncio
import http.server
import os
import socketserver
import tempfile
import threading

from roastmywebsite.core.engine import ModuleContext
from roastmywebsite.core.events import EventBus
from roastmywebsite.core.http import HttpClient
from roastmywebsite.core.scope import ScopeConfig
from roastmywebsite.vuln import exposed_files


def test_exposed_env_local():
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, ".env"), "w", encoding="utf-8") as f:
            f.write("SECRET=abc\n")

        handler = lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(*args, directory=td, **kwargs)
        httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            async def run():
                settings = type("S", (), {"timeout": 5.0, "rate_limit": 100.0, "aggressive": False})()
                scope = ScopeConfig(include=[f"127.0.0.1:{port}"], max_requests=100, rate_limit=100.0)
                bus = EventBus()
                async with HttpClient(rate_limit=100.0, timeout=5.0, verify_tls=False) as http:
                    ctx = ModuleContext(
                        target=f"127.0.0.1:{port}",
                        mode="safe",
                        settings=settings,
                        scope=scope,
                        http=http,
                        event_bus=bus,
                    )
                    await exposed_files.run(ctx)
                    assert any("Exposed environment file" in f.title for f in ctx.findings)

            asyncio.run(run())
        finally:
            httpd.shutdown()
            httpd.server_close()