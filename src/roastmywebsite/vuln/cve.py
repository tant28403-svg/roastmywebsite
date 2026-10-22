from __future__ import annotations

import re

from ..core.models import Finding, Severity


async def run(ctx) -> None:
    if not ctx.can_request():
        return
    ctx.increment()
    resp = await ctx.http.get(f"https://{ctx.target}", timeout=ctx.settings.timeout)
    if not resp.ok:
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    version_sources = []
    for key in ("server", "x-powered-by", "x-aspnet-version"):
        if key in headers:
            version_sources.append((key, headers[key]))
    for key, value in version_sources:
        if re.search(r"\d+\.\d+", value):
            ctx.add_finding(Finding(
                id=f"version-disclosure-{key}",
                title=f"Software version disclosed via {key}",
                severity=Severity.LOW,
                confidence=0.9,
                asset=str(resp.url),
                module="cve",
                description=f"{key}: {value}",
                remediation="Hide or generalize version banners.",
                tags=["information-disclosure"],
            ))

    # Optional NVD keyword search using disclosed server token
    api_key = ctx.settings.api_keys.get("nvd") if hasattr(ctx.settings, "api_keys") else None
    keyword = None
    for _, value in version_sources:
        token = value.split("/")[0].split()[0]
        if len(token) >= 3:
            keyword = token
            break
    if keyword and api_key:
        if not ctx.can_request():
            return
        ctx.increment()
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        resp = await ctx.http.get(url, params={"keywordSearch": keyword, "resultsPerPage": 5}, headers={"apiKey": api_key}, timeout=ctx.settings.timeout)
        if resp.ok:
            import json
            try:
                data = json.loads(resp.text)
            except Exception:
                return
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cid = cve.get("id")
                desc = (cve.get("descriptions") or [{}])[0].get("value", "")
                metrics = cve.get("metrics", {})
                score = None
                for keym in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(keym):
                        score = metrics[keym][0].get("cvssData", {}).get("baseScore")
                        break
                sev = Severity.MEDIUM
                if score and score >= 9:
                    sev = Severity.CRITICAL
                elif score and score >= 7:
                    sev = Severity.HIGH
                elif score and score >= 4:
                    sev = Severity.MEDIUM
                else:
                    sev = Severity.LOW
                if cid:
                    ctx.add_finding(Finding(
                        id=f"nvd-{cid}",
                        title=f"{cid}: {desc[:80]}",
                        severity=sev,
                        confidence=0.6,
                        asset=ctx.target,
                        module="cve",
                        description=desc,
                        references=[f"https://nvd.nist.gov/vuln/detail/{cid}"],
                        cve=[cid],
                        tags=["cve", "nvd"],
                    ))