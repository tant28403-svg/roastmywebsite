from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .config import CONFIG_DIR, DB_PATH, REPORT_DIR, ScanSettings, load_config, save_config
from .core import ScanEngine, get_scan, list_scans, save_scan
from .core.http import HttpClient
from .core.oob import CallbackServer, DnsCallbackServer
from .core.tools import ToolStatus, tool_status
from .interactive import run_interactive
from .modules.registry import modules_for_mode, register_all

app = typer.Typer(help="Roast My Website: OSINT and vulnerability scanner", invoke_without_command=True)
console = Console()


@app.callback()
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        run_interactive()


def _settings_from_options(
    rate: float,
    concurrency: int,
    proxy: str | None,
    timeout: float,
    aggressive: bool,
    permission: bool,
    ports_tool: str = "auto",
    subdomain_tool: str = "auto",
    nuclei_templates: str | None = None,
    nuclei_tags: str | None = None,
    nuclei_severity: str | None = None,
    nuclei_exclude_tags: str | None = None,
    stealth: bool = False,
    # WAF evasion options
    waf_evasion: bool = False,
    jitter: float = 0.0,
    rotate_ua: bool = False,
    proxy_pool: str | None = None,
    randomize_headers: bool = False,
    rotate_referer: bool = False,
    human_timing: bool = False,
    # Phase 2 options
    payload_encoding: str | None = None,
    waf_adapt: bool = False,
    auto_backoff: bool = False,
    captcha_action: str | None = None,
    # Phase 3 options
    rotate_protocol: bool = False,
    chunked: bool = False,
    pad_requests: bool = False,
    param_pollution: bool = False,
    normalize_paths: bool = False,
    doh: str | None = None,
    # Phase 4 options
    tls_rotate: bool = False,
) -> ScanSettings:
    settings = load_config()
    settings.rate_limit = rate
    settings.concurrency = concurrency
    settings.proxy = proxy
    settings.timeout = timeout
    settings.aggressive = aggressive or settings.aggressive
    settings.ports_tool = ports_tool
    settings.subdomain_tool = subdomain_tool
    settings.stealth = stealth or settings.stealth

    # WAF evasion preset expansion
    if waf_evasion:
        if jitter == 0.0:
            jitter = 1.5
        rotate_ua = True
        randomize_headers = True
        rotate_referer = True
        settings.use_cookies = True
        human_timing = True
        settings.payload_encoding = "url,case"
        settings.auto_backoff = True
        settings.waf_adapt = True
        settings.captcha_action = "skip"

    settings.waf_evasion = waf_evasion or settings.waf_evasion
    settings.jitter = jitter if jitter > 0 else settings.jitter
    settings.rotate_user_agent = rotate_ua or settings.rotate_user_agent
    if proxy_pool:
        settings.proxy_pool = [p.strip() for p in proxy_pool.split(",") if p.strip()]
    settings.randomize_headers = randomize_headers or settings.randomize_headers
    settings.rotate_referer = rotate_referer or settings.rotate_referer
    settings.human_timing = human_timing or settings.human_timing

    # Phase 2: payload encoding and adaptive detection
    if payload_encoding:
        settings.payload_encoding = payload_encoding
    settings.waf_adapt = waf_adapt or settings.waf_adapt
    settings.auto_backoff = auto_backoff or settings.auto_backoff
    if captcha_action:
        settings.captcha_action = captcha_action
    # Phase 3
    settings.rotate_protocol = rotate_protocol or settings.rotate_protocol
    settings.chunked_encoding = chunked or settings.chunked_encoding
    settings.pad_requests = pad_requests or settings.pad_requests
    settings.param_pollution = param_pollution or settings.param_pollution
    settings.normalize_paths = normalize_paths or settings.normalize_paths
    if doh:
        settings.doh_resolver = doh
    # Phase 4
    settings.tls_rotate = tls_rotate or settings.tls_rotate

    if nuclei_templates:
        settings.nuclei_templates = nuclei_templates
    if nuclei_tags:
        settings.nuclei_tags = nuclei_tags
    if nuclei_severity:
        settings.nuclei_severity = nuclei_severity
    if nuclei_exclude_tags:
        settings.nuclei_exclude_tags = nuclei_exclude_tags
    if permission:
        settings.permission_acknowledged = True
    return settings


@app.command()
def interactive() -> None:
    """Launch interactive numbered menu mode."""
    run_interactive()


@app.command()
def doctor() -> None:
    """Check runtime and external tooling."""
    console.print("[bold]Roast My Website doctor[/bold]")
    import sys
    py_status = tool_status("python3") if shutil.which("python3") else None
    if py_status is None:
        py_status = ToolStatus(name="python", available=True, version=sys.version.split()[0])
    else:
        py_status.version = py_status.version or sys.version.split()[0]
    state = "[green]ok[/green]"
    console.print(f"python: {state} {py_status.version or ''}".strip())
    for tool in ["nmap", "nuclei", "naabu", "ffuf", "subfinder", "amass"]:
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
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout"),
    ports_tool: str = typer.Option("auto", "--ports-tool", help="auto|nmap|naabu"),
    subdomain_tool: str = typer.Option("auto", "--subdomain-tool", help="auto|subfinder|amass|both"),
    nuclei_templates: str | None = typer.Option(None, "--nuclei-templates", help="Nuclei template path or directory"),
    nuclei_tags: str | None = typer.Option(None, "--nuclei-tags", help="Comma-separated tags (e.g. cve,rce,sqli)"),
    nuclei_severity: str | None = typer.Option(None, "--nuclei-severity", help="Comma-separated severities (e.g. critical,high)"),
    nuclei_exclude_tags: str | None = typer.Option(None, "--nuclei-exclude-tags", help="Comma-separated excluded tags"),
    modules: str | None = typer.Option(None, "--modules", help="Comma-separated module names to run (overrides mode)"),
    stealth: bool = typer.Option(False, "--stealth", help="Use browser User-Agent to blend in"),
    # WAF evasion
    waf_evasion: bool = typer.Option(False, "--waf-evasion", help="Enable all WAF evasion techniques"),
    jitter: float = typer.Option(0.0, "--jitter", help="Random delay per request (seconds)"),
    rotate_ua: bool = typer.Option(False, "--rotate-ua", help="Rotate User-Agent per request"),
    proxy_pool: str | None = typer.Option(None, "--proxy-pool", help="Comma-separated proxy URLs for rotation"),
    randomize_headers: bool = typer.Option(False, "--randomize-headers", help="Randomize request headers"),
    rotate_referer: bool = typer.Option(False, "--rotate-referer", help="Rotate Referer header"),
    human_timing: bool = typer.Option(False, "--human-timing", help="Human-like request timing patterns"),
    # Phase 2
    payload_encoding: str | None = typer.Option(None, "--payload-encoding", help="Payload encoding: url,double_url,case,comments,unicode,hex,all"),
    waf_adapt: bool = typer.Option(False, "--waf-adapt", help="Auto-adapt payloads to detected WAF"),
    auto_backoff: bool = typer.Option(False, "--auto-backoff", help="Auto-pause on block detection"),
    captcha_action: str | None = typer.Option(None, "--captcha-action", help="CAPTCHA handling: skip|pause|abort"),
    # Phase 3
    rotate_protocol: bool = typer.Option(False, "--rotate-protocol", help="Alternate HTTP/1.1 and HTTP/2"),
    chunked: bool = typer.Option(False, "--chunked", help="Use chunked transfer encoding"),
    pad_requests: bool = typer.Option(False, "--pad-requests", help="Pad request bodies"),
    param_pollution: bool = typer.Option(False, "--param-pollution", help="HTTP parameter pollution"),
    normalize_paths: bool = typer.Option(False, "--normalize-paths", help="Vary request paths"),
    doh: str | None = typer.Option(None, "--doh", help="DNS-over-HTTPS resolver URL"),
    # Phase 4
    tls_rotate: bool = typer.Option(False, "--tls-rotate", help="Rotate TLS/JA3 fingerprints (needs curl_cffi)"),
    output: Path | None = typer.Option(None, "--output", help="Write JSON report to path"),
) -> None:
    """Run reconnaissance only."""
    settings = _settings_from_options(rate, concurrency, proxy, timeout, False, False, ports_tool, subdomain_tool, nuclei_templates, nuclei_tags, nuclei_severity, nuclei_exclude_tags, stealth, waf_evasion=waf_evasion, jitter=jitter, rotate_ua=rotate_ua, proxy_pool=proxy_pool, randomize_headers=randomize_headers, rotate_referer=rotate_referer, human_timing=human_timing, payload_encoding=payload_encoding, waf_adapt=waf_adapt, auto_backoff=auto_backoff, captcha_action=captcha_action, rotate_protocol=rotate_protocol, chunked=chunked, pad_requests=pad_requests, param_pollution=param_pollution, normalize_paths=normalize_paths, doh=doh, tls_rotate=tls_rotate)
    asyncio.run(_run_scan(target, "recon", settings, output, modules))


@app.command()
def scan(
    target: str,
    mode: str = typer.Option("safe", "--mode", help="safe|active|aggressive"),
    rate: float = typer.Option(5.0, "--rate"),
    concurrency: int = typer.Option(20, "--concurrency"),
    proxy: str | None = typer.Option(None, "--proxy"),
    timeout: float = typer.Option(10.0, "--timeout"),
    ports_tool: str = typer.Option("auto", "--ports-tool", help="auto|nmap|naabu"),
    subdomain_tool: str = typer.Option("auto", "--subdomain-tool", help="auto|subfinder|amass|both"),
    nuclei_templates: str | None = typer.Option(None, "--nuclei-templates", help="Nuclei template path or directory"),
    nuclei_tags: str | None = typer.Option(None, "--nuclei-tags", help="Comma-separated tags (e.g. cve,rce,sqli)"),
    nuclei_severity: str | None = typer.Option(None, "--nuclei-severity", help="Comma-separated severities (e.g. critical,high)"),
    nuclei_exclude_tags: str | None = typer.Option(None, "--nuclei-exclude-tags", help="Comma-separated excluded tags"),
    modules: str | None = typer.Option(None, "--modules", help="Comma-separated module names to run (overrides mode)"),
    i_have_permission: bool = typer.Option(False, "--i-have-permission", help="Acknowledge authorization"),
    stealth: bool = typer.Option(False, "--stealth", help="Use browser User-Agent to blend in"),
    # WAF evasion
    waf_evasion: bool = typer.Option(False, "--waf-evasion", help="Enable all WAF evasion techniques"),
    jitter: float = typer.Option(0.0, "--jitter", help="Random delay per request (seconds)"),
    rotate_ua: bool = typer.Option(False, "--rotate-ua", help="Rotate User-Agent per request"),
    proxy_pool: str | None = typer.Option(None, "--proxy-pool", help="Comma-separated proxy URLs for rotation"),
    randomize_headers: bool = typer.Option(False, "--randomize-headers", help="Randomize request headers"),
    rotate_referer: bool = typer.Option(False, "--rotate-referer", help="Rotate Referer header"),
    human_timing: bool = typer.Option(False, "--human-timing", help="Human-like request timing patterns"),
    # Phase 2
    payload_encoding: str | None = typer.Option(None, "--payload-encoding", help="Payload encoding: url,double_url,case,comments,unicode,hex,all"),
    waf_adapt: bool = typer.Option(False, "--waf-adapt", help="Auto-adapt payloads to detected WAF"),
    auto_backoff: bool = typer.Option(False, "--auto-backoff", help="Auto-pause on block detection"),
    captcha_action: str | None = typer.Option(None, "--captcha-action", help="CAPTCHA handling: skip|pause|abort"),
    # Phase 3
    rotate_protocol: bool = typer.Option(False, "--rotate-protocol", help="Alternate HTTP/1.1 and HTTP/2"),
    chunked: bool = typer.Option(False, "--chunked", help="Use chunked transfer encoding"),
    pad_requests: bool = typer.Option(False, "--pad-requests", help="Pad request bodies"),
    param_pollution: bool = typer.Option(False, "--param-pollution", help="HTTP parameter pollution"),
    normalize_paths: bool = typer.Option(False, "--normalize-paths", help="Vary request paths"),
    doh: str | None = typer.Option(None, "--doh", help="DNS-over-HTTPS resolver URL"),
    # Phase 4
    tls_rotate: bool = typer.Option(False, "--tls-rotate", help="Rotate TLS/JA3 fingerprints (needs curl_cffi)"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Run vulnerability scan."""
    aggressive = mode.lower() == "aggressive"
    settings = _settings_from_options(rate, concurrency, proxy, timeout, aggressive, i_have_permission, ports_tool, subdomain_tool, nuclei_templates, nuclei_tags, nuclei_severity, nuclei_exclude_tags, stealth, waf_evasion=waf_evasion, jitter=jitter, rotate_ua=rotate_ua, proxy_pool=proxy_pool, randomize_headers=randomize_headers, rotate_referer=rotate_referer, human_timing=human_timing, payload_encoding=payload_encoding, waf_adapt=waf_adapt, auto_backoff=auto_backoff, captcha_action=captcha_action, rotate_protocol=rotate_protocol, chunked=chunked, pad_requests=pad_requests, param_pollution=param_pollution, normalize_paths=normalize_paths, doh=doh, tls_rotate=tls_rotate)
    if mode.lower() in ("active", "aggressive") and not settings.permission_acknowledged:
        if not typer.confirm("Do you own or have written permission to test this target?"):
            raise typer.Abort()
        settings.permission_acknowledged = True
    asyncio.run(_run_scan(target, mode, settings, output, modules))


@app.command()
def roast(
    target: str,
    rate: float = typer.Option(3.0, "--rate"),
    concurrency: int = typer.Option(10, "--concurrency"),
    proxy: str | None = typer.Option(None, "--proxy"),
    timeout: float = typer.Option(10.0, "--timeout"),
    ports_tool: str = typer.Option("auto", "--ports-tool", help="auto|nmap|naabu"),
    subdomain_tool: str = typer.Option("auto", "--subdomain-tool", help="auto|subfinder|amass|both"),
    nuclei_templates: str | None = typer.Option(None, "--nuclei-templates", help="Nuclei template path or directory"),
    nuclei_tags: str | None = typer.Option(None, "--nuclei-tags", help="Comma-separated tags (e.g. cve,rce,sqli)"),
    nuclei_severity: str | None = typer.Option(None, "--nuclei-severity", help="Comma-separated severities (e.g. critical,high)"),
    nuclei_exclude_tags: str | None = typer.Option(None, "--nuclei-exclude-tags", help="Comma-separated excluded tags"),
    modules: str | None = typer.Option(None, "--modules", help="Comma-separated module names to run (overrides mode)"),
    i_have_permission: bool = typer.Option(False, "--i-have-permission"),
    stealth: bool = typer.Option(False, "--stealth", help="Use browser User-Agent to blend in"),
    # WAF evasion
    waf_evasion: bool = typer.Option(False, "--waf-evasion", help="Enable all WAF evasion techniques"),
    jitter: float = typer.Option(0.0, "--jitter", help="Random delay per request (seconds)"),
    rotate_ua: bool = typer.Option(False, "--rotate-ua", help="Rotate User-Agent per request"),
    proxy_pool: str | None = typer.Option(None, "--proxy-pool", help="Comma-separated proxy URLs for rotation"),
    randomize_headers: bool = typer.Option(False, "--randomize-headers", help="Randomize request headers"),
    rotate_referer: bool = typer.Option(False, "--rotate-referer", help="Rotate Referer header"),
    human_timing: bool = typer.Option(False, "--human-timing", help="Human-like request timing patterns"),
    # Phase 2
    payload_encoding: str | None = typer.Option(None, "--payload-encoding", help="Payload encoding: url,double_url,case,comments,unicode,hex,all"),
    waf_adapt: bool = typer.Option(False, "--waf-adapt", help="Auto-adapt payloads to detected WAF"),
    auto_backoff: bool = typer.Option(False, "--auto-backoff", help="Auto-pause on block detection"),
    captcha_action: str | None = typer.Option(None, "--captcha-action", help="CAPTCHA handling: skip|pause|abort"),
    # Phase 3
    rotate_protocol: bool = typer.Option(False, "--rotate-protocol", help="Alternate HTTP/1.1 and HTTP/2"),
    chunked: bool = typer.Option(False, "--chunked", help="Use chunked transfer encoding"),
    pad_requests: bool = typer.Option(False, "--pad-requests", help="Pad request bodies"),
    param_pollution: bool = typer.Option(False, "--param-pollution", help="HTTP parameter pollution"),
    normalize_paths: bool = typer.Option(False, "--normalize-paths", help="Vary request paths"),
    doh: str | None = typer.Option(None, "--doh", help="DNS-over-HTTPS resolver URL"),
    # Phase 4
    tls_rotate: bool = typer.Option(False, "--tls-rotate", help="Rotate TLS/JA3 fingerprints (needs curl_cffi)"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Run full recon + aggressive scan."""
    settings = _settings_from_options(rate, concurrency, proxy, timeout, True, i_have_permission, ports_tool, subdomain_tool, nuclei_templates, nuclei_tags, nuclei_severity, nuclei_exclude_tags, stealth, waf_evasion=waf_evasion, jitter=jitter, rotate_ua=rotate_ua, proxy_pool=proxy_pool, randomize_headers=randomize_headers, rotate_referer=rotate_referer, human_timing=human_timing, payload_encoding=payload_encoding, waf_adapt=waf_adapt, auto_backoff=auto_backoff, captcha_action=captcha_action, rotate_protocol=rotate_protocol, chunked=chunked, pad_requests=pad_requests, param_pollution=param_pollution, normalize_paths=normalize_paths, doh=doh, tls_rotate=tls_rotate)
    if not settings.permission_acknowledged:
        if not typer.confirm("Do you own or have written permission to test this target?"):
            raise typer.Abort()
        settings.permission_acknowledged = True
    asyncio.run(_run_scan(target, "roast", settings, output, modules))


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


async def _run_scan(target: str, mode: str, settings: ScanSettings, output: Path | None, modules: str | None = None) -> None:

    engine = ScanEngine()
    register_all(engine)
    if modules:
        names = [m.strip() for m in modules.split(",") if m.strip()]
    else:
        names = modules_for_mode(mode if mode != "roast" else "aggressive")

    console.print(f"[bold]🔥 Roasting {target}[/bold] (mode={mode}, modules={len(names)})")

    def on_finding(finding) -> None:
        color = {"critical": "red", "high": "orange", "medium": "yellow", "low": "blue", "info": "grey"}.get(finding.severity.value, "white")
        console.print(f"[{color}]{finding.severity.value.upper()}[/{color}] {finding.title} ({finding.asset})")

    engine.event_bus.on("finding", on_finding)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Scanning...", total=None)

        def on_module_start(name) -> None:
            console.print(f"[cyan]▶ Running:[/cyan] {name}")
            progress.update(task, description=f"Running {name}...")
            progress.refresh()

        def on_module_done(name) -> None:
            console.print(f"[green]✓ Completed:[/green] {name}")

        def on_module_error(data) -> None:
            console.print(f"[red]✗ Module '{data['module']}' failed:[/red] {data['error']}")

        engine.event_bus.on("module_start", on_module_start)
        engine.event_bus.on("module_done", on_module_done)
        engine.event_bus.on("module_error", on_module_error)

        http_factory = lambda: HttpClient(
            rate_limit=settings.rate_limit,
            timeout=settings.timeout,
            proxy=settings.proxy,
            verify_tls=settings.verify_tls,
            user_agent=settings.user_agent,
            stealth=settings.stealth,
            stealth_user_agents=settings.stealth_user_agents,
            jitter=settings.jitter,
            rotate_user_agent=settings.rotate_user_agent,
            ua_rotation_interval=settings.ua_rotation_interval,
            proxy_pool=settings.proxy_pool,
            randomize_headers=settings.randomize_headers,
            rotate_referer=settings.rotate_referer,
            use_cookies=settings.use_cookies,
            human_timing=settings.human_timing,
            auto_backoff=settings.auto_backoff,
            backoff_cooldown=settings.backoff_cooldown,
            captcha_action=settings.captcha_action,
            rotate_protocol=settings.rotate_protocol,
            chunked_encoding=settings.chunked_encoding,
            pad_requests=settings.pad_requests,
            param_pollution=settings.param_pollution,
            normalize_paths=settings.normalize_paths,
            doh_resolver=settings.doh_resolver,
            tls_rotate=settings.tls_rotate,
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