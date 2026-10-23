
from roastmywebsite.vuln import injection
from roastmywebsite.vuln.injection import ERROR_SIGNATURES, PARAMS


class _FakeSock:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeSSock:
    def __init__(self, body="", status=200):
        self._body = body
        self._status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getpeercert(self):
        return {}

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)


class _FakeContext:
    def __init__(self, body="", status=200):
        self._body = body
        self._status = status

    def wrap_socket(self, sock, server_hostname=None):
        return _FakeSSock(self._body, self._status)


class _FakeCtx:
    def __init__(self):
        self.target = "example.com"
        self.findings = []
        self.request_count = 0
        self.max_requests = 10000

    class _Settings:
        timeout = 5.0

    settings = _Settings()

    def add_finding(self, finding):
        self.findings.append(finding)

    def can_request(self):
        return self.request_count < self.max_requests

    def increment(self):
        self.request_count += 1


def _patch(monkeypatch, body_map=None):
    """Patch http.get to return different bodies based on params."""
    if body_map is None:
        body_map = {}

    def fake_get(url, params=None, timeout=None, **kwargs):
        param = next(iter((params or {}).values())) if params else ""
        body = body_map.get(param, "")
        resp = type("R", (), {})()
        resp.text = body
        resp.status_code = 200
        resp.ok = True
        resp.headers = {}
        resp.url = url
        return resp

    class FakeClient:
        async def get(self, url, params=None, timeout=None, **kwargs):
            return fake_get(url, params, timeout, **kwargs)

        async def post(self, *a, **kw):
            r = type("R", (), {})()
            r.text = ""
            r.status_code = 200
            r.ok = True
            r.headers = {}
            r.url = ""
            return r

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr("roastmywebsite.vuln.injection.ctx" if False else "roastmywebsite.core.http.HttpClient", lambda **kw: FakeClient())


def test_error_signatures_exist():
    assert len(ERROR_SIGNATURES) > 10
    assert "sql syntax" in ERROR_SIGNATURES


def test_params_list():
    assert len(PARAMS) >= 20
    assert "id" in PARAMS
    assert "q" in PARAMS


def test_injection_imports():
    assert hasattr(injection, "run")
    assert hasattr(injection, "_probe_error_based")
    assert hasattr(injection, "_probe_boolean_based")
    assert hasattr(injection, "_probe_time_based")
    assert hasattr(injection, "_probe_union_based")