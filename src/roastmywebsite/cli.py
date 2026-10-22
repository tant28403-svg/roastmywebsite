from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .config import CONFIG_DIR, DB_PATH, REPORT_DIR, ScanSettings, load_config, save_config
from .core import ScanEngine, get_scan, list_scans, save_scan
from .core.http import HttpClient
from .core.oob import CallbackServer, DnsCallbackServer
from .core.tools import tool_status
from .modules.registry import modules_for_mode, register_all

app = typer.Typer(help="Roast My Website: OSINT and vulnerability scanner")
console = Console()


def _settings_from_options(
    rate: float,
    concurrency: int,
    proxy: str | None,
    timeout: float,
    aggressive: bool,
    permission: bool,
) -> ScanSettings:
    settings = load_config()
    settings.rate_limit = rate
    settings.concurrency = concurrency
    settings.proxy = proxy
    settings.timeout = timeout
    settings.aggressive = aggressive or settings.aggressive
    if permission:
        settings.permission_acknowledged = True
    return settings


@app.command()
def doctor() -> None:
    """Check runtime and external tooling."""
    console.print("[bold]Roast My Website doctor[/bold]")
    for tool in ["python3", "nmap", "nuclei", "naabu", "ffuf", "subfinder", "amass"]:
        status = tool_status(tool)
        state = "[green]ok[/green]" if status.available else "[red]missing[/red]"
        console.print(f"{tool}: {state} {status.version or ''}".strip())
    console.print(f"Config dir: {CONFIG_DIR}")
    console.print(f"Database: {DB_PATH}")


@app.command()
def config(
    init: bool = typer.Option(False, "--init", help="Create default config file"),
    show: bool = typer.Option(False, "--show", help="Show current config"),
) -> None:
    """Manage configuration."""
    if init:
        settings = ScanSettings()
        save_config(settings)
        console.print(f"Config written to {CONFIG_DIR / 'config.yaml'}")
    if show or not init:
        settings = load_config()
        console.print(settings)


@app.command()
def recon(
    target: str,
    rate: float = typer.Option(5.0, "--rate", help="Requests per second"),
    concurrency: int = typer.Option(20, "--concurrency", help="Concurrent requests"),
    proxy: str | None = typer.Option(None, "--proxy", help="HTTP proxy URL"),
    timeout: float = typer.Option(15.0, "--timeout", help="Request timeout"),
    output: Path | None = typer.Option(None, "--output", help="Write JSON report to path"),
) -> None:
    """Run reconnaissance only."""
    settings = _settings_from_options(rate, concurrency, proxy, timeout, False, False)
    asyncio.run(_run_scan(target, "recon", settings, output))


@app.command()
def scan(
    target: str,
    mode: str = typer.Option("safe", "--mode", help="safe|active|aggressive"),
    rate: float = typer.Option(5.0, "--rate"),
    concurrency: int = typer.Option(20, "--concurrency"),
    proxy: str | None = typer.Option(None, "--proxy"),
    timeout: float = typer.Option(15.0, "--timeout"),
    i_have_permission: bool = typer.Option(False, "--i-have-permission", help="Acknowledge authorization"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Run vulnerability scan."""
    aggressive = mode.lower() == "aggressive"
    settings = _settings_from_options(rate, concurrency, proxy, timeout, aggressive, i_have_permission)
    if mode.lower() in ("active", "aggressive") and not settings.permission_acknowledged:
        if not typer.confirm("Do you own or have written permission to test this target?"):
            raise typer.Abort()
        settings.permission_acknowledged = True
    asyncio.run(_run_scan(target, mode, settings, output))


@app.command()
def roast(
    target: str,
    rate: float = typer.Option(3.0, "--rate"),
    concurrency: int = typer.Option(10, "--concurrency"),
    proxy: str | None = typer.Option(None, "--proxy"),
    timeout: float = typer.Option(15.0, "--timeout"),
    i_have_permission: bool = typer.Option(False, "--i-have-permission"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Run full recon + aggressive scan."""
    settings = _settings_from_options(rate, concurrency, proxy, timeout, True, i_have_permission)
    if not settings.permission_acknowledged:
        if not typer.confirm("Do you own or have written permission to test this target?"):
            raise typer.Abort()
        settings.permission_acknowledged = True
    asyncio.run(_run_scan(target, "roast", settings, output))


@app.command()
def report(
    scan_id: str | None = typer.Option(None, "--scan-id", help="Scan ID (default: latest)"),
    format: str = typer.Option("html", "--format", help="json|markdown|sarif|html"),
    output: Path | None = typer.Option(None, "--output", help="Output file path"),
) -> None:
    """Generate a report from a saved scan."""
    scans = list_scans(limit=1)
    if scan_id is None:
        if not scans:
            console.print("No scans found.")
            raise typer.Exit(1)
        scan_id = scans[0]["id"]
    result = get_scan(scan_id)
    if result is None:
        console.print(f"Scan not found: {scan_id}")
        raise typer.Exit(1)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    if output is None:
        suffix = {"json": "json", "markdown": "md", "sarif": "sarif", "html": "html"}[format]
        output = REPORT_DIR / f"{scan_id}.{suffix}"
    if format == "json":
        from .reporting.json_report import write
        write(result, output)
    elif format == "markdown":
        from .reporting.markdown import write
        write(result, output)
    elif format == "sarif":
        from .reporting.sarif import write
        write(result, output)
    elif format == "html":
        from .reporting.html_report import write
        write(result, output)
    else:
        console.print(f"Unknown format: {format}")
        raise typer.Exit(1)
    console.print(f"Report written to {output}")


@app.command()
def templates(
    action: str = typer.Argument("list", help="list|validate|update|run"),
    target: str | None = typer.Argument(None, help="Target host for run"),
    path: Path | None = typer.Option(None, "--path", help="Template file or directory"),
    template_id: str | None = typer.Option(None, "--id", help="Template ID for run"),
    url: str | None = typer.Option(None, "--url", help="Archive URL for update"),
) -> None:
    """List, validate, update, or run templates."""
    from .templating.loader import load_all_templates, load_template_file, load_templates_from_dir

    if action == "update":
        from .templating.updater import update_templates

        try:
            dest = update_templates(url or "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip")
            console.print(f"Templates updated in {dest}")
        except Exception as exc:
            console.print(f"[red]Update failed:[/red] {exc}")
            raise typer.Exit(1)
        return

    if action == "run":
        from .config import ScanSettings
        from .core.engine import ModuleContext
        from .core.events import EventBus
        from .core.http import HttpClient
        from .core.scope import ScopeConfig
        from .templating.loader import load_all_templates, load_template_file
        from .templating.runner import run_template

        templates = load_all_templates()
        template = None
        if path and path.is_file():
            template = load_template_file(path)
        elif template_id:
            template = next((t for t in templates if t.id == template_id), None)
        if template is None:
            console.print("[red]Template not found.[/red]")
            raise typer.Exit(1)
        if not target:
            console.print("[red]Target is required for run.[/red]")
            raise typer.Exit(1)

        async def _run():
            settings = ScanSettings()
            scope = ScopeConfig(include=[target, f"*.{target}"])
            bus = EventBus()
            async with HttpClient(rate_limit=settings.rate_limit, timeout=settings.timeout) as http:
                ctx = ModuleContext(target=target, mode="template", settings=settings, scope=scope, http=http, event_bus=bus)
                await run_template(ctx, template)
                for finding in ctx.findings:
                    console.print(f"[bold]{finding.severity.value.upper()}[/bold] {finding.title} ({finding.asset})")

        asyncio.run(_run())
        return

    if path and path.is_file():
        template = load_template_file(path)
        if template is None:
            console.print(f"[red]Invalid template:[/red] {path}")
            raise typer.Exit(1)
        console.print(f"[green]Valid:[/green] {template.id} ({template.info.severity})")
        return
    if path and path.is_dir():
        found = load_templates_from_dir(path)
    else:
        found = load_all_templates()
    table = Table()
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Name")
    for template in found:
        table.add_row(template.id, template.info.severity, template.info.name or template.id)
    console.print(table)
    console.print(f"Total: {len(found)}")


async def _run_scan(target: str, mode: str, settings: ScanSettings, output: Path | None) -> None:

    engine = ScanEngine()
    register_all(engine)
    names = modules_for_mode(mode if mode != "roast" else "aggressive")

    console.print(f"[bold]🔥 Roasting {target}[/bold] (mode={mode}, modules={len(names)})")

    def on_finding(finding) -> None:
        color = {"critical": "red", "high": "orange", "medium": "yellow", "low": "blue", "info": "grey"}.get(finding.severity.value, "white")
        console.print(f"[{color}]{finding.severity.value.upper()}[/{color}] {finding.title} ({finding.asset})")

    engine.event_bus.on("finding", on_finding)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Scanning...", total=None)

        def on_module_start(name) -> None:
            progress.update(task, description=f"Running {name}...")

        engine.event_bus.on("module_start", on_module_start)

        http_factory = lambda: HttpClient(
            rate_limit=settings.rate_limit,
            timeout=settings.timeout,
            proxy=settings.proxy,
            verify_tls=settings.verify_tls,
            user_agent=settings.user_agent,
        )
        result = await engine.run(target, mode, settings, names, http_factory)
        progress.update(task, description="Done")

    save_scan(result)
    console.print("\n[bold]Summary[/bold]")
    table = Table()
    table.add_column("Severity")
    table.add_column("Count")
    for sev, count in result.counts.items():
        table.add_row(sev, str(count))
    console.print(table)
    console.print(f"Scan ID: {result.id}")
    console.print(f"Assets: {len(result.assets)} | Findings: {len(result.findings)}")

    if output:
        from .reporting.json_report import write as write_json

        write_json(result, output)
        console.print(f"JSON written to {output}")


@app.command()
def callback(
    http_port: int = typer.Option(8989, "--http-port", help="HTTP callback port"),
    dns_port: int = typer.Option(5353, "--dns-port", help="DNS callback port"),
) -> None:
    """Run HTTP and DNS callback servers for OOB testing."""
    async def _run():
        http = CallbackServer(port=http_port)
        dns = DnsCallbackServer(port=dns_port)
        http_ok = await http.start()
        dns_ok = await dns.start()
        console.print(f"HTTP callback: {'ok' if http_ok else 'failed'} on port {http_port}")
        console.print(f"DNS callback: {'ok' if dns_ok else 'failed'} on port {dns_port}")
        console.print("Press Ctrl+C to stop.")
        try:
            while True:
                await asyncio.sleep(1)
                if http.received:
                    console.print(f"HTTP callbacks: {sorted(http.received)}")
                    http.received.clear()
                if dns.received:
                    console.print(f"DNS callbacks: {sorted(dns.received)}")
                    dns.received.clear()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await http.stop()
            await dns.stop()

    asyncio.run(_run())


if __name__ == "__main__":
    app()