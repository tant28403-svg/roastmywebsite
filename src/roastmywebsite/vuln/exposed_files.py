from __future__ import annotations

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


async def run(ctx) -> None:
    for path, title, sev in PATHS:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
        if (not resp.ok) and ctx.can_request():
            ctx.increment()
            resp = await ctx.http.get(f"http://{ctx.target}{path}", timeout=ctx.settings.timeout)
        if resp.status_code == 200 and len(resp.text) > 0:
            ctx.add_finding(Finding(
                id=f"exposed-{path.strip('/').replace('/', '-')}",
                title=title,
                severity=sev,
                confidence=0.85,
                asset=str(resp.url),
                module="exposed_files",
                description=f"The path {path} returned HTTP 200.",
                evidence={"response": resp.text[:500]},
                remediation="Restrict access to this file or remove it from the web root.",
                tags=["exposure", "misconfiguration"],
            ))