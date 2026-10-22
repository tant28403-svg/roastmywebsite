from __future__ import annotations

from ..core.models import Finding, Severity


async def run(ctx) -> None:
    # Basic S3 bucket name permutation checks.
    base = ctx.target.split(".")[0]
    candidates = [base, f"{base}-backup", f"{base}-assets", f"{base}-static", f"{base}-dev"]
    for name in candidates:
        if not ctx.can_request():
            return
        ctx.increment()
        url = f"https://{name}.s3.amazonaws.com"
        resp = await ctx.http.get(url, timeout=ctx.settings.timeout)
        if resp.status_code == 200:
            ctx.add_finding(Finding(
                id=f"s3-open-{name}",
                title=f"Potentially open S3 bucket: {name}",
                severity=Severity.HIGH,
                confidence=0.6,
                asset=url,
                module="cloud",
                description="Bucket listing may be publicly accessible.",
                remediation="Restrict bucket ACLs and disable public listing.",
                tags=["cloud", "s3"],
            ))