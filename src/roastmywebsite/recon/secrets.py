from __future__ import annotations

import re

from ..core.models import Asset, Finding, Severity

PATTERNS = {
    # Cloud provider keys
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "google_oauth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "azure_storage_key": r"(?i)AccountKey=[A-Za-z0-9+/=]{88}",
    "azure_sas_token": r"(?i)sig=[A-Za-z0-9%+/=]{40,}",
    # Payment
    "stripe_secret": r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_publishable": r"pk_live_[0-9a-zA-Z]{24,}",
    "paypal_client_id": r"(?i)paypal.*client.?id\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{80}['\"]?",
    # Source control
    "github_token": r"ghp_[0-9a-zA-Z]{36}",
    "github_oauth": r"gho_[0-9a-zA-Z]{36}",
    "github_app": r"ghu_[0-9a-zA-Z]{36}",
    "gitlab_token": r"glpat-[0-9a-zA-Z\-_]{20}",
    # Communication
    "slack_token": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "discord_token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
    "discord_webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+",
    "telegram_bot_token": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
    # Email services
    "sendgrid_key": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    "mailgun_key": r"key-[0-9a-zA-Z]{32}",
    "mailchimp_key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "twilio_sid": r"AC[0-9a-fA-F]{32}",
    "twilio_token": r"(?i)twilio.*auth.?token\s*[:=]\s*['\"]?[0-9a-f]{32}['\"]?",
    # Auth tokens
    "jwt_token": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "bearer_token": r"(?i)bearer\s+[A-Za-z0-9\-_\.=]+",
    "basic_auth": r"(?i)basic\s+[A-Za-z0-9+/=]{10,}",
    # Database
    "mongodb_uri": r"mongodb(\+srv)?://[^\s\"'<>]+",
    "postgres_uri": r"postgres(ql)?://[^\s\"'<>]+",
    "mysql_uri": r"mysql://[^\s\"'<>]+",
    "redis_uri": r"redis://[^\s\"'<>]+",
    # Private keys
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    "ssh_private_key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    # Generic
    "generic_password": r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "generic_secret": r"(?i)secret\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "generic_api_key": r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]",
    "generic_token": r"(?i)token\s*[:=]\s*['\"][A-Za-z0-9\-_\.]{16,}['\"]",
    # Firebase
    "firebase_key": r"AIza[0-9A-Za-z\-_]{35}",
    "firebase_url": r"[a-z0-9-]+\.firebaseio\.com",
    # Misc
    "npm_token": r"npm_[A-Za-z0-9]{36}",
    "pypi_token": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}",
    "heroku_key": r"(?i)heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    # AI/ML
    "openai_key": r"sk-[A-Za-z0-9]{48}",
    "anthropic_key": r"sk-ant-[A-Za-z0-9\-_]{90,}",
    "huggingface_token": r"hf_[A-Za-z0-9]{34}",
    # More communication
    "teams_webhook": r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9\-@]+",
    "telegram_bot_token": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
    # Cloud
    "digitalocean_token": r"dop_v1_[a-f0-9]{64}",
    "cloudflare_api_key": r"(?i)cloudflare.*api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9]{37}['\"]?",
    "cloudflare_api_token": r"(?i)cloudflare.*token\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{40}['\"]?",
    # Monitoring
    "sentry_dsn": r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+",
    "datadog_api_key": r"(?i)datadog.*api[_-]?key\s*[:=]\s*['\"]?[a-f0-9]{32}['\"]?",
    # More database
    "mssql_uri": r"(?i)(mssql|sqlserver)://[^\s\"'<>]+",
    "oracle_uri": r"(?i)oracle://[^\s\"'<>]+",
    "couchdb_uri": r"(?i)couchdb?://[^\s\"'<>]+",
    "elasticsearch_uri": r"(?i)elasticsearch://[^\s\"'<>]+",
    # Generic high-entropy
    "generic_secret_key": r"(?i)(secret|private)[_-]?key\s*[:=]\s*['\"][A-Za-z0-9/+=]{20,}['\"]",
}


async def run(ctx) -> None:
    paths = ["/", "/.env", "/.env.local", "/.env.production", "/.env.staging", "/.env.development",
             "/config.js", "/main.js", "/app.js", "/bundle.js", "/vendor.js", "/chunk.js",
             "/config.json", "/settings.json", "/config.yml", "/appsettings.json",
             "/.env.example", "/config/database.yml", "/application.properties"]
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
                    id=f"secret-{name}-{path.strip('/').replace('/', '-')}",
                    title=f"Potential {name.replace('_', ' ').title()} exposed",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    asset=f"https://{ctx.target}{path}",
                    module="secrets",
                    description=f"A pattern matching {name} was found in a public response.",
                    remediation="Remove the secret from client-facing code and rotate it immediately.",
                    tags=["secret", "exposure"],
                ))