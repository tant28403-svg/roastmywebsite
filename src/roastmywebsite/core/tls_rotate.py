from __future__ import annotations

import logging

logger = logging.getLogger("roastmywebsite.tls_rotate")

# Try to import curl_cffi for TLS fingerprint rotation
try:
    from curl_cffi import requests as curl_requests
    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False
    curl_requests = None

# JA3 fingerprints to rotate through
JA3_FINGERPRINTS = [
    "chrome110",
    "chrome120",
    "safari15_5",
    "firefox102",
    "edge101",
]


def is_available() -> bool:
    return CURL_CFFI_AVAILABLE


def rotate_tls_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict | None = None,
    data: Any = None,
    timeout: float = 15.0,
    verify: bool = True,
    impersonate: str | None = None,
) -> tuple[int, dict[str, str], str, float]:
    """Make an HTTP request with a rotated TLS fingerprint using curl_cffi.

    Returns (status_code, headers, text, elapsed).
    Falls back to (0, {}, "", 0.0) if curl_cffi is not available.
    """
    if not CURL_CFFI_AVAILABLE:
        return 0, {}, "", 0.0

    import time

    import random

    if impersonate is None:
        impersonate = random.choice(JA3_FINGERPRINTS)

    start = time.monotonic()
    try:
        resp = curl_requests.request(
            method,
            url,
            headers=headers or {},
            params=params,
            data=data,
            timeout=timeout,
            verify=verify,
            impersonate=impersonate,
        )
        elapsed = time.monotonic() - start
        return resp.status_code, dict(resp.headers), resp.text, elapsed
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.debug("curl_cffi request failed: %s", exc)
        return 0, {}, "", elapsed