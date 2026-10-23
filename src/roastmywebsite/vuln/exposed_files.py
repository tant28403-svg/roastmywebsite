from __future__ import annotations

import random
import string

from ..core.models import Finding, Severity

PATHS = [
    ("/.git/HEAD", "Exposed .git repository", Severity.HIGH),
    ("/.env", "Exposed environment file", Severity.CRITICAL),
    ("/.env.local", "Exposed environment file", Severity.CRITICAL),
    ("/config.php", "Exposed configuration file", Severity.MEDIUM),
    ("/wp-config.php", "Exposed WordPress config", Severity.CRITICAL),
    ("/backup.zip", "Exposed backup archive", Severity.HIGH),
    ("/backup.sql", "Exposed SQL dump", Severity.CRITICAL),
    ("/.DS_Store", "Exposed .DS_Store file", Severity.LOW),
    ("/server-status", "Exposed Apache server-status", Severity.MEDIUM),
    ("/actuator/env", "Exposed Spring Boot actuator", Severity.HIGH),
    ("/phpinfo.php", "Exposed phpinfo()", Severity.MEDIUM),
    ("/.aws/credentials", "Exposed AWS credentials", Severity.CRITICAL),
]


async def _soft_404_baseline(ctx, host: str) -> tuple[str, int]:
    """Fetch a known-nonexistent path to detect CMS soft 404 behavior."""
    random_path = "/rmw-probe-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    try:
        resp = await ctx.http.get(f"https://{host}{random_path}", timeout=ctx.settings.timeout)
        return (resp.text[:200] if resp.ok else "", len(resp.text or ""))
    except Exception:
        return ("", 0)


async def _check_path(ctx, host: str, path: str, title: str, sev: Severity, baseline: str, baseline_len: int) -> None:
    if not ctx.can_request():
        return
    ctx.increment()
    resp = await ctx.http.get(f"https://{host}{path}", timeout=ctx.settings.timeout)
    if (not resp.ok) and ctx.can_request():
        ctx.increment()
        resp = await ctx.http.get(f"http://{host}{path}", timeout=ctx.settings.timeout)
    if resp.status_code != 200 or len(resp.text) == 0:
        return
    # Skip if the response looks like a soft 404 (same as baseline).
    if baseline and resp.text[:200] == baseline:
        return
    # Skip if the response size is very close to the baseline (soft 404).
    if baseline and abs(len(resp.text) - baseline_len) < 100:
        return
    # Skip if the response is an HTML page (likely a soft 404 or CMS page).
    content_type = (resp.headers.get("content-type") or "").lower()
    is_html = "text/html" in content_type or resp.text.lstrip().startswith("<!DOCTYPE") or resp.text.lstrip().startswith("<html")
    if is_html and path not in ("/server-status",):
        return
    # Skip if the body contains common 404 indicators.
    body_lower = (resp.text or "").lower()
    if any(indicator in body_lower for indicator in ("404", "not found", "page not found", "does not exist")):
        return
    ctx.add_finding(Finding(
        id=f"exposed-{path.strip('/').replace('/', '-')}",
        title=title,
        severity=sev,
        confidence=0.85,
        asset=str(resp.url),
        module="exposed_files",
        description=f"The path {path} returned HTTP 200 with non-HTML content.",
        evidence={"response": resp.text[:500]},
        remediation="Restrict access to this file or remove it from the web root.",
        tags=["exposure", "misconfiguration"],
    ))


async def run(ctx) -> None:
    host = ctx.target
    baseline, baseline_len = await _soft_404_baseline(ctx, host)
    # Run all path checks concurrently.
    import asyncio
    tasks = [_check_path(ctx, host, path, title, sev, baseline, baseline_len) for path, title, sev in PATHS]
    await asyncio.gather(*tasks, return_exceptions=True)