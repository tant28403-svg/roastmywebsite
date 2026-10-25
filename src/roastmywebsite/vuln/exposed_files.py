from __future__ import annotations

import random
import string

from ..core.models import Finding, Severity

PATHS = [
    # Version control
    ("/.git/HEAD", "Exposed .git repository", Severity.HIGH),
    ("/.git/config", "Exposed .git config", Severity.HIGH),
    ("/.gitignore", "Exposed .gitignore", Severity.LOW),
    ("/.svn/entries", "Exposed SVN repository", Severity.HIGH),
    ("/.hg/dirstate", "Exposed Mercurial repository", Severity.HIGH),
    # Environment files
    ("/.env", "Exposed environment file", Severity.CRITICAL),
    ("/.env.local", "Exposed environment file", Severity.CRITICAL),
    ("/.env.production", "Exposed environment file", Severity.CRITICAL),
    ("/.env.development", "Exposed environment file", Severity.CRITICAL),
    ("/.env.staging", "Exposed environment file", Severity.CRITICAL),
    ("/.env.backup", "Exposed environment file", Severity.CRITICAL),
    # Configuration files
    ("/config.php", "Exposed configuration file", Severity.MEDIUM),
    ("/config.json", "Exposed configuration file", Severity.MEDIUM),
    ("/config.yml", "Exposed configuration file", Severity.MEDIUM),
    ("/config.yaml", "Exposed configuration file", Severity.MEDIUM),
    ("/config.xml", "Exposed configuration file", Severity.MEDIUM),
    ("/wp-config.php", "Exposed WordPress config", Severity.CRITICAL),
    ("/settings.py", "Exposed Django settings", Severity.CRITICAL),
    ("/application.properties", "Exposed Spring Boot config", Severity.HIGH),
    ("/application.yml", "Exposed Spring Boot config", Severity.HIGH),
    ("/web.config", "Exposed IIS config", Severity.HIGH),
    ("/.htaccess", "Exposed Apache config", Severity.MEDIUM),
    ("/nginx.conf", "Exposed Nginx config", Severity.MEDIUM),
    ("/.aws/credentials", "Exposed AWS credentials", Severity.CRITICAL),
    ("/.docker/config.json", "Exposed Docker config", Severity.HIGH),
    # Backup files
    ("/backup.zip", "Exposed backup archive", Severity.HIGH),
    ("/backup.tar.gz", "Exposed backup archive", Severity.HIGH),
    ("/backup.sql", "Exposed SQL dump", Severity.CRITICAL),
    ("/backup.bak", "Exposed backup file", Severity.HIGH),
    ("/site.zip", "Exposed site archive", Severity.HIGH),
    ("/dump.sql", "Exposed SQL dump", Severity.CRITICAL),
    ("/db.sql", "Exposed SQL dump", Severity.CRITICAL),
    ("/database.sql", "Exposed SQL dump", Severity.CRITICAL),
    ("/backup.rar", "Exposed backup archive", Severity.HIGH),
    ("/backup.7z", "Exposed backup archive", Severity.HIGH),
    # Backup file extensions
    ("/index.php.bak", "Exposed backup file", Severity.MEDIUM),
    ("/index.php.old", "Exposed backup file", Severity.MEDIUM),
    ("/index.php~", "Exposed backup file", Severity.MEDIUM),
    ("/index.php.save", "Exposed backup file", Severity.MEDIUM),
    ("/index.php.swp", "Exposed swap file", Severity.MEDIUM),
    ("/index.php.orig", "Exposed original file", Severity.MEDIUM),
    # Server status
    ("/server-status", "Exposed Apache server-status", Severity.MEDIUM),
    ("/nginx_status", "Exposed Nginx status", Severity.MEDIUM),
    ("/status", "Exposed server status", Severity.LOW),
    ("/health", "Exposed health endpoint", Severity.LOW),
    ("/metrics", "Exposed metrics endpoint", Severity.MEDIUM),
    # Framework-specific
    ("/actuator", "Exposed Spring Boot actuator", Severity.HIGH),
    ("/actuator/env", "Exposed Spring Boot actuator env", Severity.HIGH),
    ("/actuator/health", "Exposed Spring Boot actuator health", Severity.MEDIUM),
    ("/actuator/info", "Exposed Spring Boot actuator info", Severity.MEDIUM),
    ("/actuator/mappings", "Exposed Spring Boot actuator mappings", Severity.MEDIUM),
    ("/phpinfo.php", "Exposed phpinfo()", Severity.MEDIUM),
    ("/info.php", "Exposed phpinfo()", Severity.MEDIUM),
    # Admin panels
    ("/admin", "Exposed admin panel", Severity.MEDIUM),
    ("/administrator", "Exposed admin panel", Severity.MEDIUM),
    ("/admin.php", "Exposed admin panel", Severity.MEDIUM),
    ("/wp-admin", "Exposed WordPress admin", Severity.MEDIUM),
    ("/wp-login.php", "Exposed WordPress login", Severity.LOW),
    ("/manager/html", "Exposed Tomcat manager", Severity.HIGH),
    ("/solr", "Exposed Solr admin", Severity.MEDIUM),
    ("/jenkins", "Exposed Jenkins", Severity.MEDIUM),
    ("/grafana", "Exposed Grafana", Severity.MEDIUM),
    # API docs
    ("/swagger.json", "Exposed Swagger/OpenAPI", Severity.LOW),
    ("/openapi.json", "Exposed Swagger/OpenAPI", Severity.LOW),
    ("/swagger-ui.html", "Exposed Swagger UI", Severity.LOW),
    ("/api-docs", "Exposed API docs", Severity.LOW),
    ("/docs", "Exposed documentation", Severity.LOW),
    ("/redoc", "Exposed ReDoc", Severity.LOW),
    # Other
    ("/.DS_Store", "Exposed .DS_Store file", Severity.LOW),
    ("/crossdomain.xml", "Exposed crossdomain.xml", Severity.LOW),
    ("/clientaccesspolicy.xml", "Exposed clientaccesspolicy.xml", Severity.LOW),
    ("/.well-known/security.txt", "Security.txt found", Severity.INFO),
    ("/robots.txt", "Robots.txt found", Severity.INFO),
    ("/sitemap.xml", "Sitemap found", Severity.INFO),
    # Backup file patterns for common sensitive files
    ("/.env.bak", "Exposed environment backup", Severity.CRITICAL),
    ("/.env.old", "Exposed environment backup", Severity.CRITICAL),
    ("/.env.save", "Exposed environment backup", Severity.CRITICAL),
    ("/config.php.bak", "Exposed config backup", Severity.HIGH),
    ("/config.php.old", "Exposed config backup", Severity.HIGH),
    ("/wp-config.php.bak", "Exposed WordPress config backup", Severity.CRITICAL),
    ("/database.yml.bak", "Exposed database config backup", Severity.HIGH),
    ("/settings.py.bak", "Exposed settings backup", Severity.CRITICAL),
    # Lock files (NEW)
    ("/composer.lock", "Exposed Composer lock file", Severity.LOW),
    ("/yarn.lock", "Exposed Yarn lock file", Severity.LOW),
    ("/package-lock.json", "Exposed NPM lock file", Severity.LOW),
    ("/Gemfile.lock", "Exposed Ruby lock file", Severity.LOW),
    ("/Pipfile.lock", "Exposed Pip lock file", Severity.LOW),
    ("/poetry.lock", "Exposed Poetry lock file", Severity.LOW),
    ("/go.mod", "Exposed Go module file", Severity.LOW),
    ("/go.sum", "Exposed Go checksum file", Severity.LOW),
    ("/Cargo.lock", "Exposed Rust lock file", Severity.LOW),
    # Cloud credentials (NEW)
    ("/.kube/config", "Exposed Kubernetes config", Severity.CRITICAL),
    ("/kubeconfig", "Exposed Kubernetes config", Severity.CRITICAL),
    # Framework configs (NEW)
    ("/config/database.yml", "Exposed database config", Severity.HIGH),
    ("/config/database.yaml", "Exposed database config", Severity.HIGH),
]


async def _soft_404_baseline(ctx, host: str, use_https: bool = True) -> tuple[str, int]:
    """Fetch a known-nonexistent path to detect CMS soft 404 behavior."""
    random_path = "/rmw-probe-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    scheme = "https" if use_https else "http"
    try:
        resp = await ctx.http.get(f"{scheme}://{host}{random_path}", timeout=ctx.settings.timeout)
        return (resp.text[:200] if resp.ok else "", len(resp.text or ""))
    except Exception:
        return ("", 0)


async def _check_path(ctx, host: str, path: str, title: str, sev: Severity, baseline: str, baseline_len: int, use_https: bool = True) -> None:
    if not ctx.can_request():
        return
    ctx.increment()
    scheme = "https" if use_https else "http"
    resp = await ctx.http.get(f"{scheme}://{host}{path}", timeout=ctx.settings.timeout)
    if (not resp.ok) and ctx.can_request() and use_https:
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
    # Detect whether the target speaks HTTPS or HTTP once, to avoid
    # wasting requests on a protocol that doesn't work.
    use_https = True
    if ctx.can_request():
        ctx.increment()
        probe = await ctx.http.get(f"https://{host}/", timeout=ctx.settings.timeout)
        if not probe.ok and probe.status_code == 0:
            use_https = False
    baseline, baseline_len = await _soft_404_baseline(ctx, host, use_https)
    # Run all path checks concurrently.
    import asyncio
    tasks = [_check_path(ctx, host, path, title, sev, baseline, baseline_len, use_https) for path, title, sev in PATHS]
    await asyncio.gather(*tasks, return_exceptions=True)