from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from .rate_limit import AsyncTokenBucket
from .tls_rotate import is_available as tls_rotate_available, rotate_tls_request
from .waf_detect import is_blocked, is_captcha

logger = logging.getLogger("roastmywebsite.http")

# ANSI color codes
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"

# Browser-realistic header variants for randomization
_ACCEPT_VARIANTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

_ACCEPT_LANGUAGE_VARIANTS = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.5",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,es;q=0.8",
]

_ACCEPT_ENCODING_VARIANTS = [
    "gzip, deflate, br",
    "gzip, deflate",
    "br, gzip, deflate",
]

_NOISE_HEADERS = [
    ("X-Requested-With", "XMLHttpRequest"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
    ("Cache-Control", "max-age=0"),
    ("Upgrade-Insecure-Requests", "1"),
]

_REFERER_TEMPLATES = [
    "https://www.google.com/search?q={host}",
    "https://www.bing.com/search?q={host}",
    "https://duckduckgo.com/?q={host}",
    "",  # direct (no referer)
]


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed: float
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400


class HttpClient:
    def __init__(
        self,
        rate_limit: float = 5.0,
        timeout: float = 15.0,
        proxy: str | None = None,
        verify_tls: bool = True,
        user_agent: str = "RoastMyWebsite/0.3 (+https://github.com/tant28403-svg/roastmywebsite)",
        max_retries: int = 2,
        stealth: bool = False,
        stealth_user_agents: list[str] | None = None,
        jitter: float = 0.0,
        rotate_user_agent: bool = False,
        ua_rotation_interval: int = 1,
        proxy_pool: list[str] | None = None,
        randomize_headers: bool = False,
        rotate_referer: bool = False,
        use_cookies: bool = True,
        human_timing: bool = False,
        auto_backoff: bool = False,
        backoff_cooldown: int = 30,
        captcha_action: str = "skip",
        # Phase 3
        rotate_protocol: bool = False,
        chunked_encoding: bool = False,
        pad_requests: bool = False,
        param_pollution: bool = False,
        normalize_paths: bool = False,
        doh_resolver: str | None = None,
        tls_rotate: bool = False,
        cache_enabled: bool = True,
    ):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.proxy = proxy
        self.verify_tls = verify_tls
        self.user_agent = user_agent
        self.max_retries = max_retries
        self.stealth = stealth
        self.stealth_user_agents = stealth_user_agents or []
        if self.stealth and self.stealth_user_agents:
            self.user_agent = random.choice(self.stealth_user_agents)
        self.jitter = jitter
        self.rotate_user_agent = rotate_user_agent
        self.ua_rotation_interval = max(1, ua_rotation_interval)
        self.proxy_pool = proxy_pool or []
        self.randomize_headers = randomize_headers
        self.rotate_referer = rotate_referer
        self.use_cookies = use_cookies
        self.human_timing = human_timing
        self.auto_backoff = auto_backoff
        self.backoff_cooldown = backoff_cooldown
        self.captcha_action = captcha_action
        self.bucket = AsyncTokenBucket(rate_limit, jitter=jitter)
        self._client: httpx.AsyncClient | None = None
        self._client_h2: httpx.AsyncClient | None = None
        self._request_count = 0
        self._proxy_index = 0
        self._consecutive_blocks = 0
        self._original_rate = rate_limit
        # Phase 3
        self.rotate_protocol = rotate_protocol
        self.chunked_encoding = chunked_encoding
        self.pad_requests = pad_requests
        self.param_pollution = param_pollution
        self.normalize_paths = normalize_paths
        self.doh_resolver = doh_resolver
        self.tls_rotate = tls_rotate
        self._doh_cache: dict[str, str] = {}
        # Response cache (method, url, params hash) -> HttpResponse
        self._response_cache: dict[str, HttpResponse] = {}
        self._cache_enabled: bool = cache_enabled
        self._cache_max_size: int = 256

    async def __aenter__(self) -> HttpClient:
        transport = httpx.AsyncHTTPTransport(retries=0)
        cookies = httpx.Cookies() if self.use_cookies else None
        self._client = httpx.AsyncClient(
            transport=transport,
            proxy=self.proxy,
            verify=self.verify_tls,
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            follow_redirects=True,
            cookies=cookies,
            http2=False,
        )
        if self.rotate_protocol:
            transport2 = httpx.AsyncHTTPTransport(retries=0)
            self._client_h2 = httpx.AsyncClient(
                transport=transport2,
                proxy=self.proxy,
                verify=self.verify_tls,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
                follow_redirects=True,
                cookies=cookies,
                http2=True,
            )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        if self._client_h2:
            await self._client_h2.aclose()
            self._client_h2 = None

    def _randomize_headers(self, base_headers: dict[str, str], url: str) -> dict[str, str]:
        result: dict[str, str] = {}
        items = list(base_headers.items())
        random.shuffle(items)
        for k, v in items:
            result[k] = v

        if "Accept" not in result:
            result["Accept"] = random.choice(_ACCEPT_VARIANTS)
        if "Accept-Language" not in result:
            result["Accept-Language"] = random.choice(_ACCEPT_LANGUAGE_VARIANTS)
        if "Accept-Encoding" not in result:
            result["Accept-Encoding"] = random.choice(_ACCEPT_ENCODING_VARIANTS)

        noise_count = random.randint(1, 3)
        noise_pool = list(_NOISE_HEADERS)
        random.shuffle(noise_pool)
        for k, v in noise_pool[:noise_count]:
            if k not in result:
                result[k] = v

        return result

    def _random_referer(self, url: str) -> str:
        template = random.choice(_REFERER_TEMPLATES)
        if not template:
            return ""
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""
        return template.format(host=host)

    def _normalize_path(self, url: str) -> str:
        """Vary request path with trailing slashes, case, double slashes, dot segments."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        variants = [
            path,
            path + "/" if not path.endswith("/") else path.rstrip("/"),
            path.upper() if path.islower() else path.lower(),
            "//" + path.lstrip("/") if not path.startswith("//") else path,
            "/./" + path.lstrip("/") if not path.startswith("/./") else path,
        ]
        chosen = random.choice(variants)
        return urlunparse(parsed._replace(path=chosen))

    def _pad_params(self, params: dict[str, Any] | None) -> dict[str, Any] | None:
        """Add random padding parameter to query string."""
        if params is None:
            params = {}
        params = dict(params)
        padding = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(8, 32)))
        params[f"_pad{random.randint(0, 999)}"] = padding
        return params

    def _pollute_params(self, params: dict[str, Any] | None) -> list[tuple[str, str]] | dict[str, Any] | None:
        """Duplicate parameters with benign + malicious values (HTTP Parameter Pollution)."""
        if params is None:
            return None
        # Convert to list of tuples and duplicate a random param
        items = list(params.items())
        if items and random.random() < 0.5:
            key, val = random.choice(items)
            items.append((key, val))  # duplicate
            # Add a benign variant
            items.append((key, "1"))
        return items

    async def _resolve_doh(self, hostname: str) -> str | None:
        """Resolve hostname via DNS-over-HTTPS. Returns IP or None."""
        if not self.doh_resolver:
            return None
        if hostname in self._doh_cache:
            return self._doh_cache[hostname]
        try:
            import httpx as _httpx
            async with _httpx.AsyncClient() as c:
                resp = await c.get(
                    self.doh_resolver,
                    params={"name": hostname, "type": "A"},
                    headers={"Accept": "application/dns-json"},
                    timeout=10.0,
                )
                data = resp.json()
                for answer in data.get("Answer", []):
                    if answer.get("type") == 1:  # A record
                        ip = answer.get("data")
                        if ip:
                            self._doh_cache[hostname] = ip
                            return ip
        except Exception:
            pass
        return None

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
        json: Any = None,
        allow_redirects: bool = True,
        timeout: float | None = None,
    ) -> HttpResponse:
        assert self._client is not None
        await self.bucket.acquire()

        effective_url = url
        effective_params = params

        # Response cache check (GET only)
        cache_key = None
        if self._cache_enabled and method.upper() == "GET":
            import hashlib
            cache_input = f"{method}:{effective_url}:{effective_params}:{headers}"
            cache_key = hashlib.md5(cache_input.encode()).hexdigest()
            if cache_key in self._response_cache:
                cached = self._response_cache[cache_key]
                return HttpResponse(
                    url=cached.url,
                    status_code=cached.status_code,
                    headers=dict(cached.headers),
                    text=cached.text,
                    elapsed=0.0,
                    error=cached.error,
                )

        if self.human_timing and random.random() < 0.2:
            await asyncio.sleep(random.uniform(2.0, 5.0))

        effective_timeout = self.timeout if timeout is None else timeout
        last_error: str | None = None

        if self.rotate_user_agent and self.stealth_user_agents:
            if self._request_count % self.ua_rotation_interval == 0:
                self.user_agent = random.choice(self.stealth_user_agents)
            self._request_count += 1

        proxies = None
        if self.proxy_pool:
            proxies = self.proxy_pool[self._proxy_index % len(self.proxy_pool)]
            self._proxy_index += 1

        effective_headers = dict(headers or {})
        effective_headers.setdefault("User-Agent", self.user_agent)

        if self.randomize_headers:
            effective_headers = self._randomize_headers(effective_headers, url)

        if self.rotate_referer and "Referer" not in (headers or {}):
            ref = self._random_referer(url)
            if ref:
                effective_headers["Referer"] = ref

        # Phase 3: chunked encoding
        if self.chunked_encoding and data is not None and not isinstance(data, (str, bytes, dict)):
            effective_headers.setdefault("Transfer-Encoding", "chunked")

        # Phase 3: path normalization
        effective_url = url
        if self.normalize_paths:
            effective_url = self._normalize_path(url)

        # Phase 3: request padding
        effective_params = params
        if self.pad_requests:
            effective_params = self._pad_params(effective_params)

        # Phase 3: parameter pollution
        if self.param_pollution:
            effective_params = self._pollute_params(effective_params)

        # Phase 3: DoH resolution
        if self.doh_resolver:
            try:
                parsed = urlparse(effective_url)
                hostname = parsed.hostname
                if hostname and not hostname.replace(".", "").isdigit():
                    ip = await self._resolve_doh(hostname)
                    if ip:
                        # Replace hostname with IP, keep Host header
                        effective_headers.setdefault("Host", hostname)
                        effective_url = effective_url.replace(hostname, ip, 1)
            except Exception:
                pass

        # Select client (protocol switching)
        client = self._client
        if self.rotate_protocol and self._client_h2 and random.random() < 0.5:
            client = self._client_h2

        for attempt in range(self.max_retries + 1):
            start = asyncio.get_event_loop().time()
            try:
                # TLS rotation via curl_cffi
                if self.tls_rotate and tls_rotate_available():
                    import asyncio as _asyncio
                    status, resp_headers, text, elapsed = await _asyncio.to_thread(
                        rotate_tls_request,
                        method,
                        effective_url,
                        headers=effective_headers,
                        params=effective_params,
                        data=data,
                        timeout=effective_timeout,
                        verify=self.verify_tls,
                    )
                    if status > 0:
                        self._consecutive_blocks = 0 if status < 400 else self._consecutive_blocks
                        return HttpResponse(
                            url=effective_url,
                            status_code=status,
                            headers=resp_headers,
                            text=text,
                            elapsed=elapsed,
                        )

                request_kwargs: dict[str, Any] = {
                    "method": method,
                    "url": effective_url,
                    "headers": effective_headers,
                    "params": effective_params,
                    "data": data,
                    "json": json,
                    "follow_redirects": allow_redirects,
                    "timeout": effective_timeout,
                }
                if proxies:
                    request_kwargs["proxy"] = proxies

                response = await client.request(**request_kwargs)
                elapsed = asyncio.get_event_loop().time() - start

                if self.auto_backoff and is_blocked(response.status_code, response.text):
                    self._consecutive_blocks += 1
                    if self._consecutive_blocks >= 3:
                        logger.warning(
                            f"{RED}Block detected{RESET} (status={YELLOW}%d{RESET}). Backing off for {CYAN}%ds{RESET}...",
                            response.status_code, self.backoff_cooldown,
                        )
                        new_rate = max(0.5, self.rate_limit * 0.5)
                        self.bucket = AsyncTokenBucket(new_rate, jitter=self.jitter)
                        if self.proxy_pool:
                            self._proxy_index = (self._proxy_index + 1) % len(self.proxy_pool)
                        await asyncio.sleep(self.backoff_cooldown)
                        self._consecutive_blocks = 0
                elif response.status_code < 400:
                    self._consecutive_blocks = 0

                if is_captcha(response.text):
                    if self.captcha_action == "abort":
                        raise RuntimeError("CAPTCHA detected, aborting.")
                    elif self.captcha_action == "pause":
                        logger.warning("CAPTCHA detected. Pausing for manual solving...")
                        await asyncio.sleep(60)
                    else:
                        logger.debug("CAPTCHA detected in response.")

                result = HttpResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    text=response.text,
                    elapsed=elapsed,
                )
                # Cache the response
                if cache_key and self._cache_enabled:
                    if len(self._response_cache) >= self._cache_max_size:
                        # Evict oldest (first key)
                        first_key = next(iter(self._response_cache))
                        del self._response_cache[first_key]
                    self._response_cache[cache_key] = result
                return result
            except Exception as exc:
                last_error = str(exc)
                if attempt < self.max_retries:
                    await asyncio.sleep(0.2 * (attempt + 1))
        return HttpResponse(url=url, status_code=0, headers={}, text="", elapsed=0.0, error=last_error)

    async def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("HEAD", url, **kwargs)