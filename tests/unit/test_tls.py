import asyncio
import warnings

from roastmywebsite.vuln import tls
from roastmywebsite.vuln.tls import _legacy_probe_context

warnings.filterwarnings("ignore")


class _FakeSock:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeSSock:
    def __init__(self, protocol="TLSv1.3", cipher=("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)):
        self._protocol = protocol
        self._cipher = cipher

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getpeercert(self):
        return {"notAfter": "Dec 31 23:59:59 2030 GMT"}

    def version(self):
        return self._protocol

    def cipher(self):
        return self._cipher


class _FakeContext:
    def __init__(self, ssock):
        self._ssock = ssock

    def wrap_socket(self, sock, server_hostname=None):
        return self._ssock


class _FakeCtx:
    def __init__(self):
        self.target = "example.com"
        self.findings = []
        self.request_count = 0
        self.max_requests = 1000

    class _Settings:
        timeout = 10.0

    settings = _Settings()

    def add_finding(self, finding):
        self.findings.append(finding)

    def can_request(self):
        return self.request_count < self.max_requests

    def increment(self):
        self.request_count += 1


def _patch(monkeypatch, protocol="TLSv1.3", cipher=("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128), legacy=None):
    monkeypatch.setattr(tls.socket, "create_connection", lambda addr, timeout=0: _FakeSock())
    monkeypatch.setattr(
        tls.ssl, "create_default_context", lambda: _FakeContext(_FakeSSock(protocol, cipher))
    )
    monkeypatch.setattr(tls, "_probe_legacy_protocol", lambda host, timeout: legacy)


def _ids(ctx):
    return {f.id for f in ctx.findings}


def test_legacy_probe_context_builds():
    context = _legacy_probe_context()
    assert context.verify_mode.name == "CERT_NONE"
    assert context.check_hostname is False


def test_weak_protocol_detected_via_legacy_probe(monkeypatch):
    _patch(monkeypatch, protocol="TLSv1.3", legacy="TLSv1")
    ctx = _FakeCtx()
    asyncio.run(tls.run(ctx))
    assert "tls-weak-protocol" in _ids(ctx)


def test_weak_protocol_detected_when_negotiated(monkeypatch):
    _patch(monkeypatch, protocol="TLSv1", legacy=None)
    ctx = _FakeCtx()
    asyncio.run(tls.run(ctx))
    finding = next(f for f in ctx.findings if f.id == "tls-weak-protocol")
    assert "TLSv1" in finding.title


def test_modern_target_has_no_weak_protocol(monkeypatch):
    _patch(monkeypatch, protocol="TLSv1.3", legacy=None)
    ctx = _FakeCtx()
    asyncio.run(tls.run(ctx))
    assert "tls-weak-protocol" not in _ids(ctx)


def test_weak_cipher_rc4(monkeypatch):
    _patch(monkeypatch, cipher=("RC4-SHA", "TLSv1.2", 128))
    ctx = _FakeCtx()
    asyncio.run(tls.run(ctx))
    assert "tls-weak-cipher" in _ids(ctx)


def test_weak_cipher_3des(monkeypatch):
    _patch(monkeypatch, cipher=("DES-CBC3-SHA", "TLSv1.2", 112))
    ctx = _FakeCtx()
    asyncio.run(tls.run(ctx))
    assert "tls-weak-cipher" in _ids(ctx)


def test_strong_cipher_has_no_finding(monkeypatch):
    _patch(monkeypatch, cipher=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256))
    ctx = _FakeCtx()
    asyncio.run(tls.run(ctx))
    assert "tls-weak-cipher" not in _ids(ctx)


def test_expired_certificate(monkeypatch):
    class _ExpiredSSock(_FakeSSock):
        def getpeercert(self):
            return {"notAfter": "Jan 1 00:00:00 2000 GMT"}

    _patch(monkeypatch)
    monkeypatch.setattr(tls.ssl, "create_default_context", lambda: _FakeContext(_ExpiredSSock()))
    ctx = _FakeCtx()
    asyncio.run(tls.run(ctx))
    assert "tls-expired" in _ids(ctx)
