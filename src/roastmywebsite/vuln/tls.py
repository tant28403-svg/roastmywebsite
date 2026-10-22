from __future__ import annotations

import socket
import ssl

from ..core.models import Finding, Severity


async def run(ctx) -> None:
    host = ctx.target
    port = 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=ctx.settings.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
    except Exception as exc:
        ctx.add_finding(Finding(
            id="tls-connection-failed",
            title="TLS connection failed",
            severity=Severity.MEDIUM,
            confidence=0.8,
            asset=host,
            module="tls",
            description=str(exc),
            remediation="Verify TLS configuration and certificate.",
            tags=["tls"],
        ))
        return

    if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        ctx.add_finding(Finding(
            id="tls-weak-protocol",
            title=f"Weak TLS protocol enabled: {protocol}",
            severity=Severity.HIGH,
            confidence=1.0,
            asset=host,
            module="tls",
            remediation="Disable TLS 1.0/1.1 and SSL; enable TLS 1.2/1.3 only.",
            tags=["tls"],
        ))
    if cipher and "RC4" in str(cipher) or (cipher and "3DES" in str(cipher)):
        ctx.add_finding(Finding(
            id="tls-weak-cipher",
            title="Weak TLS cipher detected",
            severity=Severity.MEDIUM,
            confidence=0.9,
            asset=host,
            module="tls",
            remediation="Disable weak ciphers.",
            tags=["tls"],
        ))
    # Expiry check
    import datetime as _dt
    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            if expiry < _dt.datetime.utcnow():
                ctx.add_finding(Finding(id="tls-expired", title="TLS certificate expired", severity=Severity.HIGH, confidence=1.0, asset=host, module="tls", remediation="Renew the certificate.", tags=["tls"]))
            elif (expiry - _dt.datetime.utcnow()).days < 30:
                ctx.add_finding(Finding(id="tls-expiring", title="TLS certificate expires within 30 days", severity=Severity.MEDIUM, confidence=1.0, asset=host, module="tls", remediation="Renew the certificate soon.", tags=["tls"]))
        except ValueError:
            pass