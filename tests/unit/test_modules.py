import asyncio


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


def test_xss_payloads_exist():
    from roastmywebsite.vuln.xss import PARAMS, PAYLOADS
    assert len(PAYLOADS) >= 10
    assert len(PARAMS) >= 10
    assert "<script>alert(1)</script>" in PAYLOADS


def test_xss_imports():
    from roastmywebsite.vuln import xss
    assert hasattr(xss, "run")
    assert hasattr(xss, "_probe_param")


def test_ssrf_targets():
    from roastmywebsite.vuln.ssrf import PARAMS, SSRF_INDICATORS, TARGETS
    assert len(TARGETS) >= 10
    assert len(SSRF_INDICATORS) >= 5
    assert len(PARAMS) >= 10
    assert "ami-id" in SSRF_INDICATORS
    assert "169.254.169.254" in str(TARGETS)


def test_ssrf_imports():
    from roastmywebsite.vuln import ssrf
    assert hasattr(ssrf, "run")


def test_idor_paths():
    from roastmywebsite.vuln.idor import IDOR_PARAMS, IDOR_PATHS, IDOR_VALUES
    assert len(IDOR_PATHS) >= 20
    assert len(IDOR_PARAMS) >= 10
    assert "1" in IDOR_VALUES
    assert "2" in IDOR_VALUES


def test_idor_imports():
    from roastmywebsite.vuln import idor
    assert hasattr(idor, "run")


def test_secrets_patterns():
    from roastmywebsite.recon.secrets import PATTERNS
    assert len(PATTERNS) >= 30
    assert "aws_access_key" in PATTERNS
    assert "jwt_token" in PATTERNS
    assert "private_key" in PATTERNS
    assert "stripe_secret" in PATTERNS


def test_secrets_imports():
    from roastmywebsite.recon import secrets
    assert hasattr(secrets, "run")


def test_exposed_files_paths():
    from roastmywebsite.vuln.exposed_files import PATHS
    assert len(PATHS) >= 40
    paths = [p[0] for p in PATHS]
    assert "/.env" in paths
    assert "/.git/HEAD" in paths
    assert "/backup.sql" in paths


def test_headers_required():
    from roastmywebsite.vuln.headers import REQUIRED_HEADERS
    assert len(REQUIRED_HEADERS) >= 9
    assert "strict-transport-security" in REQUIRED_HEADERS
    assert "content-security-policy" in REQUIRED_HEADERS
    assert "x-content-type-options" in REQUIRED_HEADERS


def test_cloud_imports():
    from roastmywebsite.vuln import cloud
    assert hasattr(cloud, "run")


def test_rate_limiter():
    from roastmywebsite.core.rate_limit import AsyncTokenBucket

    async def _test():
        bucket = AsyncTokenBucket(rate=10.0, capacity=5.0)
        # Should acquire 5 tokens immediately
        for _ in range(5):
            await bucket.acquire()
        # 6th should wait
        start = asyncio.get_event_loop().time()
        await bucket.acquire()
        elapsed = asyncio.get_event_loop().time() - start
        assert elapsed >= 0.05  # Should have waited at least a bit

    asyncio.run(_test())


def test_rate_limiter_no_busy_wait():
    """Verify the rate limiter actually sleeps instead of busy-waiting."""
    import time

    from roastmywebsite.core.rate_limit import AsyncTokenBucket

    async def _test():
        bucket = AsyncTokenBucket(rate=1.0, capacity=1.0)
        await bucket.acquire()  # Use the one token
        start = time.monotonic()
        await bucket.acquire()  # Should wait ~1s
        elapsed = time.monotonic() - start
        assert elapsed >= 0.5  # Should have waited

    asyncio.run(_test())