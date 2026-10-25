from __future__ import annotations

from ..core.models import Asset, Finding, Severity

ENDPOINT_PATTERNS = [
    r"""["'](\/[a-zA-Z0-9_\-\/\.]+)["']""",
    r"""fetch\(["']([^"']+)["']""",
    r"""axios\.[a-z]+\(["']([^"']+)["']""",
    r"""XMLHttpRequest.*open\(["'][A-Z]+["'],\s*["']([^"']+)["']""",
    r"""\.get\(["']([^"']+)["']""",
    r"""\.post\(["']([^"']+)["']""",
    r"""endpoint\s*[:=]\s*["']([^"']+)["']""",
    r"""api[_-]?url\s*[:=]\s*["']([^"']+)["']""",
    r"""baseURL\s*[:=]\s*["']([^"']+)["']""",
]

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"sk_live_[0-9a-zA-Z]{24}",
    r"ghp_[0-9a-zA-Z]{36}",
    r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
]

SOURCE_MAP_PATTERN = r"sourceMappingURL=([^\s]+)"


async def run(ctx) -> None:
    if not ctx.can_request():
        return
    ctx.increment()
    resp = await ctx.http.get(f"https://{ctx.target}", timeout=ctx.settings.timeout)
    if not resp.ok:
        return
    import re as _re
    scripts = _re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", resp.text, _re.IGNORECASE)
    seen: set[str] = set()
    for src in scripts[:50]:
        if not ctx.can_request():
            return
        url = src if src.startswith("http") else f"https://{ctx.target}/{src.lstrip('/')}"
        if url in seen:
            continue
        seen.add(url)
        ctx.increment()
        r = await ctx.http.get(url, timeout=ctx.settings.timeout)
        if not r.ok:
            continue
        # Extract endpoints
        for pat in ENDPOINT_PATTERNS:
            for match in _re.findall(pat, r.text):
                endpoint = match if isinstance(match, str) else match[0]
                if endpoint.startswith("/") and len(endpoint) < 120:
                    ctx.add_asset(Asset(value=endpoint, asset_type="js_endpoint", source="js", metadata={"script": url}))
        # Extract secrets
        for pat in SECRET_PATTERNS:
            for match in _re.findall(pat, r.text):
                ctx.add_asset(Asset(value=match, asset_type="secret", source="js", metadata={"script": url}))
                ctx.add_finding(Finding(
                    id=f"secret-js-{pat[:10]}",
                    title="Potential secret in JavaScript",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    asset=url,
                    module="js",
                    description=f"A secret pattern was found in {url}.",
                    remediation="Remove secrets from client-side code and rotate them.",
                    tags=["secret", "javascript"],
                ))
        # Check for source maps
        sm_match = _re.search(SOURCE_MAP_PATTERN, r.text)
        if sm_match:
            sm_url = sm_match.group(1)
            if not sm_url.startswith("http"):
                sm_url = url.rsplit("/", 1)[0] + "/" + sm_url
            ctx.add_asset(Asset(value=sm_url, asset_type="source_map", source="js", metadata={"script": url}))
            ctx.add_finding(Finding(
                id=f"source-map-{url.split('/')[-1]}",
                title="JavaScript source map exposed",
                severity=Severity.MEDIUM,
                confidence=0.9,
                asset=sm_url,
                module="js",
                description=f"A source map was found for {url}, which may expose original source code.",
                remediation="Remove source maps from production builds.",
                tags=["information-disclosure", "javascript"],
            ))
            # Try to fetch the source map and extract additional endpoints
            if ctx.can_request():
                ctx.increment()
                sm_resp = await ctx.http.get(sm_url, timeout=ctx.settings.timeout)
                if sm_resp.ok:
                    try:
                        sm_data = __import__("json").loads(sm_resp.text)
                        sources = sm_data.get("sources", [])
                        for src in sources[:50]:
                            if src and not src.startswith("webpack") and not src.startswith("node_modules"):
                                ctx.add_asset(Asset(value=src, asset_type="source_file", source="js", metadata={"source_map": sm_url}))
                    except Exception:
                        pass
        # Detect common JS frameworks
        framework_sigs = {
            "react": ["react", "react-dom", "__NEXT_DATA__", "createElement"],
            "vue": ["vue.js", "vue.min.js", "__VUE__", "Vue.component"],
            "angular": ["angular", "ng-version", "angular.min.js"],
            "jquery": ["jquery", "jQuery"],
            "webpack": ["webpack", "__webpack_require__"],
            "vite": ["vite", "__vite"],
        }
        for fw, sigs in framework_sigs.items():
            if any(sig.lower() in r.text.lower() for sig in sigs):
                ctx.add_asset(Asset(value=fw, asset_type="js_framework", source="js", metadata={"script": url}))

        # Dependency analysis: check for known vulnerable JS library versions
        vuln_libs = {
            "jquery": [("1.", "2.", "3.4", "3.5.0", "3.5.1"), "CVE-2020-11022, CVE-2020-11023"],
            "angular": [("1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"), "Multiple XSS CVEs"],
            "lodash": [("4.17.0", "4.17.1", "4.17.2", "4.17.3", "4.17.4"), "CVE-2019-10744 (prototype pollution)"],
            "moment": [("2.19", "2.20", "2.21", "2.22"), "CVE-2022-24785 (ReDoS)"],
            "bootstrap": [("3.", "4.0", "4.1", "4.2", "4.3.0", "4.3.1"), "CVE-2019-8331 (XSS)"],
        }
        for lib, (versions, cves) in vuln_libs.items():
            if lib in r.text.lower():
                # Try to extract version
                import re as _re2
                version_match = _re2.search(rf"{lib}[^\"']*?(\d+\.\d+[\.\d]*)", r.text, _re2.IGNORECASE)
                if version_match:
                    ver = version_match.group(1)
                    if any(ver.startswith(v) for v in versions):
                        ctx.add_finding(Finding(
                            id=f"vuln-js-lib-{lib}",
                            title=f"Potentially vulnerable {lib} version {ver}",
                            severity=Severity.MEDIUM,
                            confidence=0.6,
                            asset=url,
                            module="js",
                            description=f"Detected {lib} {ver} which may be affected by: {cves}.",
                            remediation=f"Update {lib} to the latest version.",
                            tags=["javascript", "dependency", "vulnerable-lib"],
                        ))