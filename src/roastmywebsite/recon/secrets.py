from __future__ import annotations

import re

from ..core.models import Asset, Finding, Severity

PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "stripe_secret": r"sk_live_[0-9a-zA-Z]{24}",
    "github_token": r"ghp_[0-9a-zA-Z]{36}",
    "generic_password": r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
}


async def run(ctx) -> None:
    # Scan main page and common files
    paths = ["/", "/.env", "/config.js", "/main.js"]
    for path in paths:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(f"https://{ctx.target}{path}", timeout=ctx.settings.timeout)
        if not resp.ok:
            continue
        for name, pattern in PATTERNS.items():
            for match in re.finditer(pattern, resp.text):
                value = match.group(0)
                ctx.add_asset(Asset(value=value[:80], asset_type="secret", source="secrets", metadata={"pattern": name, "path": path}))
                ctx.add_finding(Finding(
                    id=f"secret-{name}-{path}",
                    title=f"Potential {name.replace('_', ' ').title()} exposed",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    asset=f"https://{ctx.target}{path}",
                    module="secrets",
                    description=f"A pattern matching {name} was found in a public response.",
                    remediation="Remove the secret from client-facing code and rotate it immediately.",
                    tags=["secret", "exposure"],
                ))