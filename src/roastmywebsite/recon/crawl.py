from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..core.models import Asset

MAX_PAGES = 100


def _same_host(url: str, host: str) -> bool:
    return urlparse(url).hostname == host or urlparse(url).hostname == f"www.{host}"


async def run(ctx) -> None:
    base_host = ctx.target
    start_urls = [f"https://{base_host}", f"http://{base_host}"]
    visited: set[str] = set()
    queue: deque[str] = deque()
    for u in start_urls:
        queue.append(u)

    while queue and len(visited) < MAX_PAGES:
        if not ctx.can_request():
            return
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        ctx.increment()
        resp = await ctx.http.get(url, timeout=ctx.settings.timeout)
        if not resp.ok:
            continue
        ctx.add_asset(Asset(value=url, asset_type="crawled_url", source="crawl", metadata={"status": resp.status_code}))
        try:
            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            soup = BeautifulSoup(resp.text, "html.parser")

        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            parsed = urlparse(link)
            if parsed.scheme not in ("http", "https"):
                continue
            if not _same_host(link, base_host):
                continue
            clean = parsed._replace(fragment="").geturl()
            if clean not in visited:
                queue.append(clean)

        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action", ""))
            method = form.get("method", "GET").upper()
            inputs = [i.get("name") for i in form.find_all("input") if i.get("name")]
            ctx.add_asset(Asset(value=action, asset_type="form", source="crawl", metadata={"method": method, "inputs": inputs}))

    # robots.txt and sitemap
    for path in ("/robots.txt", "/sitemap.xml"):
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(f"https://{base_host}{path}", timeout=ctx.settings.timeout)
        if resp.ok:
            ctx.add_asset(Asset(value=f"https://{base_host}{path}", asset_type="metadata_file", source="crawl"))
            if path == "/robots.txt":
                for line in resp.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        p = line.split(":", 1)[1].strip()
                        if p:
                            ctx.add_asset(Asset(value=p, asset_type="disallowed_path", source="crawl"))