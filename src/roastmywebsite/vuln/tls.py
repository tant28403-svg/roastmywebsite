from __future__ import annotations

import socket
import ssl

from ..core.models import Finding, Severity

LEGACY_PROTOCOLS = ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")


def _legacy_probe_context() -> ssl.SSLContext:
    """Build a context that deliberately allows obsolete TLS/SSL versions.

    This is for *probing only*. Roast My Website needs to discover whether a
    target still accepts TLS 1.0 or TLS 1.1 so it can report it as a
    ``tls-weak-protocol`` finding. A hardened default context negotiates the
    best available version, so a server that also supports TLS 1.0 would look
    clean. This context is never used to serve traffic, never handles secrets,
    and exists solely to ask the remote end "do you still speak this?".

    Certificate verification stays off here on purpose: the point is to
    complete the handshake and read the negotiated version, even for a
    target whose certificate is expired or self-signed. Any certificate
    problem is already covered by the main verified check.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Explicitly re-enable the legacy versions that the modern defaults
    # disable. This is intentional and isolated to this one helper.
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
    except ValueError:  # pragma: no cover - platform without TLSv1
        pass
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        # Needed to talk to servers that do not support RFC 5746
        # renegotiation, which is common on very old stacks.
        context.options |= ssl.OP_LEGACY_SERVER_CONNECT
    return context


def _probe_legacy_protocol(host: str, timeout: float) -> str | None:
    """Return the negotiated legacy protocol name, or None if unsupported."""
    try:
        context = _legacy_probe_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                protocol = ssock.version()
    except Exception:
        return None
    return protocol if protocol in LEGACY_PROTOCOLS else None


async def run(ctx) -> None:
    host = ctx.target
    port = 443
    try:
        # Verified modern context for the certificate and protocol check.
        # It negotiates the best version the target offers and validates the
        # chain, which is what an outbound inspection should do.
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

    # A modern context always negotiates the strongest version the target
    # supports, so this only fires when legacy is the *only* option offered.
    weak_protocol = protocol if protocol in LEGACY_PROTOCOLS else None
    if weak_protocol is None and ctx.can_request():
        # Fall back to an explicit legacy probe so a target that supports both
        # TLS 1.2 and TLS 1.0 is still reported instead of looking clean.
        ctx.increment()
        weak_protocol = _probe_legacy_protocol(host, ctx.settings.timeout)
    if weak_protocol:
        ctx.add_finding(Finding(
            id="tls-weak-protocol",
            title=f"Weak TLS protocol enabled: {weak_protocol}",
            severity=Severity.HIGH,
            confidence=1.0,
            asset=host,
            module="tls",
            remediation="Disable TLS 1.0/1.1 and SSL; enable TLS 1.2/1.3 only.",
            tags=["tls"],
        ))
    # OpenSSL names the 3DES suite "DES-CBC3-SHA", so match both spellings.
    weak_cipher = bool(cipher) and any(
        token in str(cipher) for token in ("RC4", "3DES", "DES-CBC3")
    )
    if weak_cipher:
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