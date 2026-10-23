from __future__ import annotations

from ..core.models import Finding, Severity


async def run(ctx) -> None:
    base = ctx.target.split(".")[0]

    # S3 bucket name permutations
    s3_candidates = [base, f"{base}-backup", f"{base}-assets", f"{base}-static", f"{base}-dev", f"{base}-prod", f"{base}-staging", f"{base}-files", f"{base}-uploads", f"{base}-media"]
    for name in s3_candidates:
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
                tags=["cloud", "s3", "aws"],
            ))

    # Azure Blob Storage
    azure_candidates = [base, f"{base}backup", f"{base}assets", f"{base}static", f"{base}dev"]
    for name in azure_candidates:
        if not ctx.can_request():
            return
        ctx.increment()
        url = f"https://{name}.blob.core.windows.net"
        resp = await ctx.http.get(url, timeout=ctx.settings.timeout)
        if resp.status_code == 200 and "xml" in (resp.headers.get("content-type") or "").lower():
            ctx.add_finding(Finding(
                id=f"azure-open-{name}",
                title=f"Potentially open Azure Blob Storage: {name}",
                severity=Severity.HIGH,
                confidence=0.6,
                asset=url,
                module="cloud",
                description="Azure Blob container listing may be publicly accessible.",
                remediation="Restrict container access and disable public listing.",
                tags=["cloud", "azure", "blob"],
            ))

    # GCP Cloud Storage
    gcp_candidates = [base, f"{base}-backup", f"{base}-assets", f"{base}-static", f"{base}-dev"]
    for name in gcp_candidates:
        if not ctx.can_request():
            return
        ctx.increment()
        url = f"https://storage.googleapis.com/{name}"
        resp = await ctx.http.get(url, timeout=ctx.settings.timeout)
        if resp.status_code == 200 and "xml" in (resp.headers.get("content-type") or "").lower():
            ctx.add_finding(Finding(
                id=f"gcp-open-{name}",
                title=f"Potentially open GCP Cloud Storage: {name}",
                severity=Severity.HIGH,
                confidence=0.6,
                asset=url,
                module="cloud",
                description="GCP bucket listing may be publicly accessible.",
                remediation="Restrict bucket IAM policies and disable public listing.",
                tags=["cloud", "gcp", "gcs"],
            ))

    # Firebase Realtime Database
    firebase_candidates = [base, f"{base}-backup", f"{base}-dev", f"{base}-staging"]
    for name in firebase_candidates:
        if not ctx.can_request():
            return
        ctx.increment()
        url = f"https://{name}.firebaseio.com/.json"
        resp = await ctx.http.get(url, timeout=ctx.settings.timeout)
        if resp.status_code == 200 and resp.text not in ("null", "null\n", ""):
            ctx.add_finding(Finding(
                id=f"firebase-open-{name}",
                title=f"Potentially open Firebase database: {name}",
                severity=Severity.CRITICAL,
                confidence=0.7,
                asset=url,
                module="cloud",
                description="Firebase Realtime Database may be publicly readable.",
                remediation="Restrict Firebase database rules to authenticated users.",
                tags=["cloud", "firebase", "database"],
            ))

    # DigitalOcean Spaces
    do_candidates = [base, f"{base}-backup", f"{base}-assets", f"{base}-static"]
    for name in do_candidates:
        if not ctx.can_request():
            return
        ctx.increment()
        url = f"https://{name}.nyc3.digitaloceanspaces.com"
        resp = await ctx.http.get(url, timeout=ctx.settings.timeout)
        if resp.status_code == 200 and "xml" in (resp.headers.get("content-type") or "").lower():
            ctx.add_finding(Finding(
                id=f"do-open-{name}",
                title=f"Potentially open DigitalOcean Space: {name}",
                severity=Severity.HIGH,
                confidence=0.6,
                asset=url,
                module="cloud",
                description="DigitalOcean Space listing may be publicly accessible.",
                remediation="Restrict Space ACLs and disable public listing.",
                tags=["cloud", "digitalocean", "spaces"],
            ))