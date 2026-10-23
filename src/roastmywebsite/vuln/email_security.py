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
    for selector in ("default", "google", "selector1", "selector2", "k1", "s1", "s2", "dkim", "mail", "smtp", "key1", "key2"):
        try:
            await asyncio.to_thread(dns.resolver.resolve, f"{selector}._domainkey.{domain}", "TXT")
            return
        except Exception:
            continue
    ctx.add_finding(Finding(id="missing-dkim", title="No common DKIM selector found", severity=Severity.LOW, confidence=0.6, asset=domain, module="email_security", remediation="Configure DKIM signing.", tags=["email", "dns"]))

    # MTA-STS check
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, f"_mta-sts.{domain}", "TXT")
        mta_sts = [str(a) for a in answers]
    except Exception:
        mta_sts = []
    if not mta_sts:
        ctx.add_finding(Finding(id="missing-mta-sts", title="Missing MTA-STS record", severity=Severity.LOW, confidence=0.7, asset=domain, module="email_security", remediation="Publish an MTA-STS TXT record for email transport security.", tags=["email", "dns", "mta-sts"]))
    else:
        # Check MTA-STS policy file
        try:
            resp = await ctx.http.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout=ctx.settings.timeout)
            if not resp.ok:
                ctx.add_finding(Finding(id="mta-sts-policy-missing", title="MTA-STS policy file not accessible", severity=Severity.LOW, confidence=0.7, asset=domain, module="email_security", remediation="Ensure mta-sts.txt is accessible at https://mta-sts.{domain}/.well-known/mta-sts.txt", tags=["email", "dns", "mta-sts"]))
        except Exception:
            pass

    # TLS-RPT check
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, f"_smtp._tls.{domain}", "TXT")
        tls_rpt = [str(a) for a in answers]
    except Exception:
        tls_rpt = []
    if not tls_rpt:
        ctx.add_finding(Finding(id="missing-tls-rpt", title="Missing TLS-RPT record", severity=Severity.LOW, confidence=0.7, asset=domain, module="email_security", remediation="Publish a TLS-RPT TXT record for TLS reporting.", tags=["email", "dns", "tls-rpt"]))

    # SPF analysis
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, "TXT")
        texts = [str(a) for a in answers]
        spf_records = [t for t in texts if "v=spf1" in t.lower()]
        if spf_records:
            spf = spf_records[0].lower()
            if ("+all" in spf or " ~all" not in spf and " -all" not in spf and " ?all" not in spf) and "all" in spf and not any(q in spf for q in ["~all", "-all", "?all"]):
                ctx.add_finding(Finding(id="spf-too-permissive", title="SPF record may be too permissive", severity=Severity.MEDIUM, confidence=0.7, asset=domain, module="email_security", remediation="Use ~all or -all instead of +all or no qualifier.", tags=["email", "dns", "spf"]))
            if "include:" in spf and spf.count("include:") > 10:
                ctx.add_finding(Finding(id="spf-too-many-includes", title="SPF record has too many includes", severity=Severity.LOW, confidence=0.7, asset=domain, module="email_security", remediation="Reduce SPF includes to avoid DNS lookup limit (max 10).", tags=["email", "dns", "spf"]))
    except Exception:
        pass

    # DMARC analysis
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(a) for a in answers]
        if dmarc_records:
            dmarc = dmarc_records[0].lower()
            if "p=none" in dmarc:
                ctx.add_finding(Finding(id="dmarc-policy-none", title="DMARC policy set to none", severity=Severity.LOW, confidence=0.9, asset=domain, module="email_security", remediation="Upgrade DMARC policy from p=none to p=quarantine or p=reject.", tags=["email", "dns", "dmarc"]))
    except Exception:
        pass