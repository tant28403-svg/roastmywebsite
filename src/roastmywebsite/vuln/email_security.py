from __future__ import annotations

import dns.resolver

from ..core.models import Finding, Severity


async def run(ctx) -> None:
    import asyncio

    domain = ctx.target
    # SPF
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, "TXT")
        texts = [str(a) for a in answers]
    except Exception:
        texts = []
    spf = any("v=spf1" in t for t in texts)
    if not spf:
        ctx.add_finding(Finding(id="missing-spf", title="Missing SPF record", severity=Severity.MEDIUM, confidence=0.9, asset=domain, module="email_security", remediation="Publish an SPF TXT record.", tags=["email", "dns"]))
    # DMARC
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, f"_dmarc.{domain}", "TXT")
        dmarc = [str(a) for a in answers]
    except Exception:
        dmarc = []
    if not dmarc:
        ctx.add_finding(Finding(id="missing-dmarc", title="Missing DMARC record", severity=Severity.MEDIUM, confidence=0.9, asset=domain, module="email_security", remediation="Publish a DMARC TXT record.", tags=["email", "dns"]))
    # DKIM common selector
    for selector in ("default", "google", "selector1", "selector2"):
        try:
            await asyncio.to_thread(dns.resolver.resolve, f"{selector}._domainkey.{domain}", "TXT")
            return
        except Exception:
            continue
    ctx.add_finding(Finding(id="missing-dkim", title="No common DKIM selector found", severity=Severity.LOW, confidence=0.6, asset=domain, module="email_security", remediation="Configure DKIM signing.", tags=["email", "dns"]))