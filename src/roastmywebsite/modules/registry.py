from __future__ import annotations

from ..recon import crawl, ct, dns, js, ports, secrets, subdomains, tech, wayback
from ..vuln import (
    api,
    auth,
    browser,
    cloud,
    cve,
    dns_oob,
    dom_xss,
    email_security,
    exposed_files,
    headers,
    idor,
    injection,
    nuclei,
    oob,
    ssrf,
    templates,
    tls,
    xss,
)

MODULES = {
    "dns": dns.run,
    "subdomains": subdomains.run,
    "ports": ports.run,
    "tech": tech.run,
    "crawl": crawl.run,
    "js": js.run,
    "secrets": secrets.run,
    "ct": ct.run,
    "wayback": wayback.run,
    "headers": headers.run,
    "exposed_files": exposed_files.run,
    "tls": tls.run,
    "cve": cve.run,
    "dns_oob": dns_oob.run,
    "dom_xss": dom_xss.run,
    "nuclei": nuclei.run,
    "injection": injection.run,
    "xss": xss.run,
    "ssrf": ssrf.run,
    "auth": auth.run,
    "idor": idor.run,
    "api": api.run,
    "browser": browser.run,
    "oob": oob.run,
    "cloud": cloud.run,
    "email_security": email_security.run,
    "templates": templates.run,
}


def register_all(engine) -> None:
    for name, func in MODULES.items():
        engine.register(name, func)


SAFE_MODULES = [
    "dns", "subdomains", "ct", "wayback", "tech", "ports", "crawl", "js", "secrets",
    "headers", "exposed_files", "tls", "cve", "nuclei", "api", "cloud", "email_security", "templates",
]

ACTIVE_MODULES = SAFE_MODULES + ["injection", "xss", "ssrf", "idor"]

AGGRESSIVE_MODULES = ACTIVE_MODULES + ["auth", "browser", "dns_oob", "dom_xss", "oob"]

RECON_MODULES = ["dns", "subdomains", "ct", "wayback", "tech", "ports", "crawl", "js", "secrets", "api"]


def modules_for_mode(mode: str) -> list[str]:
    mode = mode.lower()
    if mode == "recon":
        return list(RECON_MODULES)
    if mode in ("safe",):
        return list(SAFE_MODULES)
    if mode in ("active",):
        return list(ACTIVE_MODULES)
    if mode in ("aggressive", "roast", "full"):
        return list(AGGRESSIVE_MODULES)
    return list(SAFE_MODULES)