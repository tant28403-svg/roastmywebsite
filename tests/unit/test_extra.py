import asyncio


def test_tls_imports():
    from roastmywebsite.vuln import tls
    assert hasattr(tls, "run")
    assert hasattr(tls, "_legacy_probe_context")
    assert hasattr(tls, "_probe_legacy_protocol")
    assert hasattr(tls, "LEGACY_PROTOCOLS")


def test_tls_legacy_protocols():
    from roastmywebsite.vuln.tls import LEGACY_PROTOCOLS
    assert "TLSv1" in LEGACY_PROTOCOLS
    assert "TLSv1.1" in LEGACY_PROTOCOLS
    assert "SSLv3" in LEGACY_PROTOCOLS
    assert "SSLv2" in LEGACY_PROTOCOLS


def test_auth_imports():
    from roastmywebsite.vuln import auth
    assert hasattr(auth, "run")
    assert hasattr(auth, "DEFAULT_CREDS")
    assert hasattr(auth, "_analyze_jwt")


def test_auth_default_creds():
    from roastmywebsite.vuln.auth import DEFAULT_CREDS
    assert len(DEFAULT_CREDS) >= 20
    assert ("admin", "admin") in DEFAULT_CREDS


def test_auth_jwt_analysis():
    from roastmywebsite.vuln.auth import _analyze_jwt

    async def _test():
        # Create a fake context
        class FakeCtx:
            def __init__(self):
                self.target = "example.com"
                self.findings = []

            def add_finding(self, f):
                self.findings.append(f)

        ctx = FakeCtx()
        # JWT with "none" algorithm
        import base64
        import json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "123", "exp": 1000}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}."
        await _analyze_jwt(ctx, token)
        assert len(ctx.findings) > 0
        assert any("none" in f.id for f in ctx.findings)

    asyncio.run(_test())


def test_dom_xss_imports():
    from roastmywebsite.vuln import dom_xss
    assert hasattr(dom_xss, "run")


def test_browser_imports():
    from roastmywebsite.vuln import browser
    assert hasattr(browser, "run")


def test_templates_imports():
    from roastmywebsite.vuln import templates
    assert hasattr(templates, "run")


def test_oob_imports():
    from roastmywebsite.vuln import oob
    assert hasattr(oob, "run")


def test_dns_oob_imports():
    from roastmywebsite.vuln import dns_oob
    assert hasattr(dns_oob, "run")


def test_tech_signatures():
    from roastmywebsite.recon.tech import SIGNATURES
    assert len(SIGNATURES) >= 10
    assert "wordpress" in SIGNATURES
    assert "react" in SIGNATURES


def test_exposed_files_count():
    from roastmywebsite.vuln.exposed_files import PATHS
    assert len(PATHS) >= 50


def test_js_patterns():
    from roastmywebsite.recon.js import ENDPOINT_PATTERNS, SECRET_PATTERNS
    assert len(ENDPOINT_PATTERNS) >= 5
    assert len(SECRET_PATTERNS) >= 4


def test_api_paths():
    from roastmywebsite.vuln.api import API_PATHS, COMMON_API_ENDPOINTS, SPEC_PATHS
    assert len(SPEC_PATHS) >= 15
    assert len(API_PATHS) >= 10
    assert len(COMMON_API_ENDPOINTS) >= 10


def test_crawl_backup_exts():
    # Verify crawl module has backup file discovery
    import inspect

    from roastmywebsite.recon import crawl
    src = inspect.getsource(crawl.run)
    assert "backup_exts" in src or ".bak" in src


def test_interactive_imports():
    from roastmywebsite.interactive import (
        AGGRESSIVE_MODULES,
        MODES,
        RECON_MODULES,
        VULN_MODULES,
    )
    assert len(MODES) == 6
    assert len(RECON_MODULES) == 9
    assert len(VULN_MODULES) == 13
    assert len(AGGRESSIVE_MODULES) == 5


def test_cli_modules_option():
    import inspect

    from roastmywebsite.cli import _run_scan
    sig = inspect.signature(_run_scan)
    assert "modules" in sig.parameters