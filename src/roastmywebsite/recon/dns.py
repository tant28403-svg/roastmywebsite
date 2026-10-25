from __future__ import annotations

import asyncio
import socket

import dns.resolver

from ..core.models import Asset, Finding, Severity


async def run(ctx) -> None:
    host = ctx.target
    resolver = dns.resolver.Resolver()
    resolver.timeout = ctx.settings.timeout
    resolver.lifetime = ctx.settings.timeout

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]
    for rtype in record_types:
        if not ctx.can_request():
            return
        ctx.increment()
        try:
            answers = await asyncio.to_thread(resolver.resolve, host, rtype)
        except Exception:
            continue
        for answer in answers:
            value = str(answer).rstrip(".")
            ctx.add_asset(Asset(value=value, asset_type=f"dns_{rtype.lower()}", source="dns", metadata={"host": host}))
        if rtype == "TXT":
            for answer in answers:
                text = str(answer)
                if "v=spf1" in text.lower():
                    ctx.add_asset(Asset(value=text, asset_type="spf", source="dns"))

    # Reverse DNS for A records
    try:
        infos = await asyncio.to_thread(socket.gethostbyname_ex, host)
        for ip in infos[2]:
            try:
                ptr = await asyncio.to_thread(socket.gethostbyaddr, ip)
                ctx.add_asset(Asset(value=ptr[0], asset_type="ptr", source="dns", metadata={"ip": ip}))
            except Exception:
                pass
    except Exception:
        pass

    # DNS zone transfer attempt (AXFR)
    try:
        import dns.query as _dns_query
        import dns.zone as _dns_zone
        ns_records = await asyncio.to_thread(resolver.resolve, host, "NS")
        for ns in ns_records:
            ns_name = str(ns).rstrip(".")
            try:
                zone = await asyncio.to_thread(_dns_zone.from_xfr, _dns_query.xfr(ns_name, host, timeout=ctx.settings.timeout))
                if zone:
                    ctx.add_finding(Finding(
                        id="dns-zone-transfer",
                        title="DNS zone transfer (AXFR) allowed",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        asset=host,
                        module="dns",
                        description=f"Zone transfer succeeded from {ns_name}.",
                        remediation="Disable AXFR on DNS servers.",
                        tags=["dns", "zone-transfer"],
                    ))
                    for name in zone.nodes:
                        ctx.add_asset(Asset(value=str(name), asset_type="zone_record", source="dns", metadata={"ns": ns_name}))
            except Exception:
                pass
    except Exception:
        pass

    # DNSSEC check
    try:
        answers = await asyncio.to_thread(resolver.resolve, host, "DNSKEY")
        if answers:
            ctx.add_asset(Asset(value="DNSSEC enabled", asset_type="dnssec", source="dns"))
        else:
            ctx.add_finding(Finding(
                id="dns-no-dnssec",
                title="DNSSEC not enabled",
                severity=Severity.LOW,
                confidence=0.8,
                asset=host,
                module="dns",
                description="No DNSKEY records found. DNSSEC is not enabled.",
                remediation="Enable DNSSEC for your domain.",
                tags=["dns", "dnssec"],
            ))
    except Exception:
        ctx.add_finding(Finding(
            id="dns-no-dnssec",
            title="DNSSEC not enabled",
            severity=Severity.LOW,
            confidence=0.8,
            asset=host,
            module="dns",
            description="No DNSKEY records found. DNSSEC is not enabled.",
            remediation="Enable DNSSEC for your domain.",
            tags=["dns", "dnssec"],
        ))

    # Wildcard DNS detection
    try:
        import random, string
        random_sub = "".join(random.choices(string.ascii_lowercase, k=20))
        random_host = f"{random_sub}.{host}"
        infos = await asyncio.to_thread(socket.gethostbyname_ex, random_host)
        if infos[2]:
            ctx.add_finding(Finding(
                id="dns-wildcard",
                title="Wildcard DNS record detected",
                severity=Severity.LOW,
                confidence=0.9,
                asset=host,
                module="dns",
                description=f"Random subdomain {random_host} resolves to {infos[2]}, indicating wildcard DNS.",
                remediation="Remove wildcard DNS if not needed. Wildcards can enable subdomain takeover.",
                tags=["dns", "wildcard"],
            ))
    except Exception:
        pass

    # DNS rebinding detection (check if domain resolves to internal IP)
    try:
        infos = await asyncio.to_thread(socket.gethostbyname_ex, host)
        for ip in infos[2]:
            if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                ctx.add_finding(Finding(
                    id="dns-rebinding",
                    title="Domain resolves to internal IP address",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    asset=host,
                    module="dns",
                    description=f"Domain {host} resolves to internal IP {ip}, potential DNS rebinding.",
                    remediation="Ensure public domains do not resolve to internal IPs.",
                    tags=["dns", "rebinding", "ssrf"],
                ))
    except Exception:
        pass