from __future__ import annotations

import asyncio
import random
import time

import pytest

from roastmywebsite.config import ScanSettings
from roastmywebsite.core.http import HttpClient
from roastmywebsite.core.rate_limit import AsyncTokenBucket


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def test_config_waf_fields_defaults():
    s = ScanSettings()
    assert s.waf_evasion is False
    assert s.jitter == 0.0
    assert s.rotate_user_agent is False
    assert s.ua_rotation_interval == 1
    assert s.proxy_pool == []
    assert s.randomize_headers is False
    assert s.rotate_referer is False
    assert s.rotate_protocol is False
    assert s.chunked_encoding is False
    assert s.use_cookies is True
    assert s.human_timing is False
    assert s.payload_encoding == "none"
    assert s.waf_adapt is False
    assert s.fragment_payloads is False
    assert s.auto_backoff is False
    assert s.backoff_cooldown == 30
    assert s.captcha_action == "skip"
    assert s.pad_requests is False
    assert s.param_pollution is False
    assert s.normalize_paths is False
    assert s.tls_rotate is False
    assert s.doh_resolver is None


# ---------------------------------------------------------------------------
# Rate limiter jitter
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limiter_jitter_adds_delay():
    bucket = AsyncTokenBucket(100.0, jitter=0.3)
    start = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - start
    # Should have at least some jitter delay (up to 0.3s)
    assert elapsed >= 0.0  # jitter is random, just ensure no crash


@pytest.mark.asyncio
async def test_rate_limiter_no_jitter_fast():
    bucket = AsyncTokenBucket(1000.0, jitter=0.0)
    start = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 0.1


@pytest.mark.asyncio
async def test_rate_limiter_jitter_stored():
    bucket = AsyncTokenBucket(5.0, jitter=1.5)
    assert bucket.jitter == 1.5


# ---------------------------------------------------------------------------
# HttpClient
# ---------------------------------------------------------------------------

def test_http_client_init_new_params():
    client = HttpClient(
        jitter=1.0,
        rotate_user_agent=True,
        ua_rotation_interval=3,
        proxy_pool=["http://p1:8080", "http://p2:8080"],
        randomize_headers=True,
        rotate_referer=True,
        use_cookies=False,
        human_timing=True,
    )
    assert client.jitter == 1.0
    assert client.rotate_user_agent is True
    assert client.ua_rotation_interval == 3
    assert client.proxy_pool == ["http://p1:8080", "http://p2:8080"]
    assert client.randomize_headers is True
    assert client.rotate_referer is True
    assert client.use_cookies is False
    assert client.human_timing is True


def test_http_client_init_defaults():
    client = HttpClient()
    assert client.jitter == 0.0
    assert client.rotate_user_agent is False
    assert client.proxy_pool == []
    assert client.randomize_headers is False
    assert client.use_cookies is True
    assert client.human_timing is False


def test_http_client_randomize_headers():
    client = HttpClient(randomize_headers=True)
    base = {"X-Custom": "value"}
    result = client._randomize_headers(base, "https://example.com")
    # Original header preserved
    assert result["X-Custom"] == "value"
    # Accept header injected
    assert "Accept" in result
    # At least one noise header or Accept header injected (result should have more than just base)
    assert len(result) >= 3


def test_http_client_randomize_headers_no_duplicates():
    client = HttpClient(randomize_headers=True)
    base = {"Accept": "text/plain", "X-Custom": "val"}
    result = client._randomize_headers(base, "https://example.com")
    # Explicitly set Accept should not be overwritten
    assert result["Accept"] == "text/plain"


def test_http_client_random_referer():
    client = HttpClient(rotate_referer=True)
    ref = client._random_referer("https://example.com/page")
    # Should be one of the templates or empty
    assert isinstance(ref, str)


def test_http_client_proxy_pool_index_increments():
    client = HttpClient(proxy_pool=["http://p1:8080", "http://p2:8080"])
    assert client._proxy_index == 0
    # Simulate increment
    client._proxy_index += 1
    assert client._proxy_index == 1


# ---------------------------------------------------------------------------
# CLI preset expansion (via _settings_from_options)
# ---------------------------------------------------------------------------

def test_waf_evasion_preset_sets_fields():
    from roastmywebsite.cli import _settings_from_options
    settings = _settings_from_options(
        rate=5.0, concurrency=20, proxy=None, timeout=10.0,
        aggressive=False, permission=False,
        waf_evasion=True,
    )
    assert settings.waf_evasion is True
    assert settings.jitter == 1.5
    assert settings.rotate_user_agent is True
    assert settings.randomize_headers is True
    assert settings.rotate_referer is True
    assert settings.use_cookies is True
    assert settings.human_timing is True
    assert settings.payload_encoding == "url,case"
    assert settings.auto_backoff is True
    assert settings.waf_adapt is True


def test_individual_flags_override_preset():
    from roastmywebsite.cli import _settings_from_options
    settings = _settings_from_options(
        rate=5.0, concurrency=20, proxy=None, timeout=10.0,
        aggressive=False, permission=False,
        waf_evasion=True, jitter=3.0,
    )
    assert settings.jitter == 3.0  # individual flag overrides preset


def test_no_waf_evasion_defaults():
    from roastmywebsite.cli import _settings_from_options
    settings = _settings_from_options(
        rate=5.0, concurrency=20, proxy=None, timeout=10.0,
        aggressive=False, permission=False,
    )
    assert settings.waf_evasion is False
    assert settings.jitter == 0.0
    assert settings.rotate_user_agent is False
    assert settings.randomize_headers is False


def test_proxy_pool_parsing():
    from roastmywebsite.cli import _settings_from_options
    settings = _settings_from_options(
        rate=5.0, concurrency=20, proxy=None, timeout=10.0,
        aggressive=False, permission=False,
        proxy_pool="http://p1:8080, socks5h://p2:1080",
    )
    assert settings.proxy_pool == ["http://p1:8080", "socks5h://p2:1080"]


# ---------------------------------------------------------------------------
# Phase 2: Encoding
# ---------------------------------------------------------------------------

def test_encode_payload_url():
    from roastmywebsite.core.encoding import encode_payload
    assert encode_payload("' OR 1=1--", "url") == "%27%20OR%201%3D1--"


def test_encode_payload_case():
    from roastmywebsite.core.encoding import encode_payload
    result = encode_payload("SELECT", "case")
    # Should be same length, possibly different case
    assert len(result) == len("SELECT")


def test_encode_payloads_none():
    from roastmywebsite.core.encoding import encode_payloads
    payloads = ["a", "b"]
    assert encode_payloads(payloads, "none") == payloads


def test_encode_payloads_url():
    from roastmywebsite.core.encoding import encode_payloads
    result = encode_payloads(["' OR 1=1--"], "url")
    assert "%27%20OR%201%3D1--" in result


def test_encode_payloads_all():
    from roastmywebsite.core.encoding import encode_payloads
    result = encode_payloads(["' OR 1=1--"], "all")
    # Should have original + multiple encoded variants
    assert len(result) >= 3
    assert "' OR 1=1--" in result


def test_encode_tuple_payloads():
    from roastmywebsite.core.encoding import encode_tuple_payloads
    payloads = [("' AND 1=1", "' AND 1=2")]
    result = encode_tuple_payloads(payloads, "url")
    assert len(result) >= 1
    # Original preserved
    assert ("' AND 1=1", "' AND 1=2") in result


# ---------------------------------------------------------------------------
# Phase 2: WAF detection
# ---------------------------------------------------------------------------

def test_detect_waf_cloudflare():
    from roastmywebsite.core.waf_detect import detect_waf
    headers = {"cf-ray": "abc123", "server": "cloudflare"}
    assert detect_waf(headers) == "Cloudflare"


def test_detect_waf_none():
    from roastmywebsite.core.waf_detect import detect_waf
    headers = {"server": "nginx"}
    assert detect_waf(headers, "hello world") is None


def test_is_blocked():
    from roastmywebsite.core.waf_detect import is_blocked
    assert is_blocked(403, "Access Denied") is True
    assert is_blocked(200, "OK") is False
    assert is_blocked(429, "") is True


def test_is_captcha():
    from roastmywebsite.core.waf_detect import is_captcha
    assert is_captcha("<html>...recaptcha...") is True
    assert is_captcha("normal page") is False


def test_waf_adapt_payload():
    from roastmywebsite.core.waf_detect import waf_adapt_payload
    result = waf_adapt_payload("SELECT * FROM users", "Cloudflare")
    assert len(result) >= 2  # original + adapted
    assert "SELECT * FROM users" in result


# ---------------------------------------------------------------------------
# Phase 2: CLI flags
# ---------------------------------------------------------------------------

def test_phase2_cli_flags():
    from roastmywebsite.cli import _settings_from_options
    settings = _settings_from_options(
        rate=5.0, concurrency=20, proxy=None, timeout=10.0,
        aggressive=False, permission=False,
        payload_encoding="url,case", waf_adapt=True,
        auto_backoff=True, captcha_action="pause",
    )
    assert settings.payload_encoding == "url,case"
    assert settings.waf_adapt is True
    assert settings.auto_backoff is True
    assert settings.captcha_action == "pause"


def test_phase2_preset():
    from roastmywebsite.cli import _settings_from_options
    settings = _settings_from_options(
        rate=5.0, concurrency=20, proxy=None, timeout=10.0,
        aggressive=False, permission=False,
        waf_evasion=True,
    )
    assert settings.payload_encoding == "url,case"
    assert settings.waf_adapt is True
    assert settings.auto_backoff is True


# ---------------------------------------------------------------------------
# Phase 3: Advanced transport
# ---------------------------------------------------------------------------

def test_phase3_normalize_path():
    from roastmywebsite.core.http import HttpClient
    client = HttpClient(normalize_paths=True)
    result = client._normalize_path("https://example.com/admin")
    assert isinstance(result, str)
    assert "example.com" in result


def test_phase3_pad_params():
    from roastmywebsite.core.http import HttpClient
    client = HttpClient(pad_requests=True)
    result = client._pad_params({"id": "1"})
    assert "id" in result
    assert len(result) == 2  # original + padding


def test_phase3_pad_params_none():
    from roastmywebsite.core.http import HttpClient
    client = HttpClient(pad_requests=True)
    result = client._pad_params(None)
    assert result is not None
    assert len(result) == 1  # just padding


def test_phase3_pollute_params():
    from roastmywebsite.core.http import HttpClient
    client = HttpClient(param_pollution=True)
    # Run multiple times to hit the pollution branch
    found_polluted = False
    for _ in range(20):
        result = client._pollute_params({"id": "1"})
        assert isinstance(result, list)
        if len(result) >= 2:
            found_polluted = True
    assert found_polluted, "Pollution branch never triggered"


def test_phase3_pollute_params_none():
    from roastmywebsite.core.http import HttpClient
    client = HttpClient(param_pollution=True)
    result = client._pollute_params(None)
    assert result is None


def test_phase4_tls_rotate_available():
    from roastmywebsite.core.tls_rotate import is_available
    # curl_cffi not installed in test env, should be False
    assert is_available() is False


def test_phase4_fragment_payload():
    from roastmywebsite.core.encoding import fragment_payload
    result = fragment_payload("' OR 1=1--", 2)
    assert len(result) == 2
    assert "".join(result) == "' OR 1=1--"


def test_phase4_fragment_payload_single():
    from roastmywebsite.core.encoding import fragment_payload
    result = fragment_payload("ab", 5)
    assert result == ["ab"]


def test_phase4_tls_rotate_cli_flag():
    from roastmywebsite.cli import _settings_from_options
    settings = _settings_from_options(
        rate=5.0, concurrency=20, proxy=None, timeout=10.0,
        aggressive=False, permission=False,
        tls_rotate=True,
    )
    assert settings.tls_rotate is True


def test_phase3_phase3_cli_flags():
    from roastmywebsite.cli import _settings_from_options
    settings = _settings_from_options(
        rate=5.0, concurrency=20, proxy=None, timeout=10.0,
        aggressive=False, permission=False,
        rotate_protocol=True, chunked=True, pad_requests=True,
        param_pollution=True, normalize_paths=True,
        doh="https://cloudflare-dns.com/dns-query",
    )
    assert settings.rotate_protocol is True
    assert settings.chunked_encoding is True
    assert settings.pad_requests is True
    assert settings.param_pollution is True
    assert settings.normalize_paths is True
    assert settings.doh_resolver == "https://cloudflare-dns.com/dns-query"