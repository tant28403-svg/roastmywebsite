from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from .rate_limit import AsyncTokenBucket


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
        user_agent: str = "RoastMyWebsite/0.1",
        max_retries: int = 2,
    ):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.proxy = proxy
        self.verify_tls = verify_tls
        self.user_agent = user_agent
        self.max_retries = max_retries
        self.bucket = AsyncTokenBucket(rate_limit)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HttpClient:
        transport = httpx.AsyncHTTPTransport(retries=0)
        self._client = httpx.AsyncClient(
            transport=transport,
            proxy=self.proxy,
            verify=self.verify_tls,
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

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
        effective_timeout = self.timeout if timeout is None else timeout
        last_error: str | None = None
        for attempt in range(self.max_retries + 1):
            start = asyncio.get_event_loop().time()
            try:
                response = await self._client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json,
                    follow_redirects=allow_redirects,
                    timeout=effective_timeout,
                )
                elapsed = asyncio.get_event_loop().time() - start
                return HttpResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    text=response.text,
                    elapsed=elapsed,
                )
            except Exception as exc:
                last_error = str(exc)
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (attempt + 1))
        return HttpResponse(url=url, status_code=0, headers={}, text="", elapsed=0.0, error=last_error)

    async def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("HEAD", url, **kwargs)