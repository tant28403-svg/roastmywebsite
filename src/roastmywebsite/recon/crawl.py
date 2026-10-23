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

        # Extract HTML comments
        import re as _re
        comments = _re.findall(r"<!--(.*?)-->", resp.text, _re.DOTALL)
        for comment in comments:
            comment = comment.strip()
            if len(comment) > 10 and len(comment) < 500:
                ctx.add_asset(Asset(value=comment[:200], asset_type="html_comment", source="crawl", metadata={"url": url}))

        # Extract parameters from URLs
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            parsed = urlparse(link)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        key = param.split("=")[0]
                        ctx.add_asset(Asset(value=key, asset_type="url_parameter", source="crawl", metadata={"url": link}))

    # Backup file discovery
    backup_exts = [".bak", ".old", ".swp", ".orig", ".save", "~", ".tmp"]
    for ext in backup_exts:
        if not ctx.can_request():
            return
        ctx.increment()
        resp = await ctx.http.get(f"https://{base_host}/index.php{ext}", timeout=ctx.settings.timeout)
        if resp.ok and len(resp.text) > 0:
            ctx.add_asset(Asset(value=f"https://{base_host}/index.php{ext}", asset_type="backup_file", source="crawl"))

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

    # Optional ffuf content discovery
    from ..core.tools import run_tool, which

    if which("ffuf"):
        import os
        import tempfile
        wordlist = None
        # Try common wordlist locations
        for wl in ["/usr/share/wordlists/dirb/common.txt", "/usr/share/seclists/Discovery/Web-Content/common.txt", "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt", "/usr/share/ffuf/wordlist.txt"]:
            if os.path.isfile(wl):
                wordlist = wl
                break
        if wordlist and ctx.can_request():
            ctx.increment()
            out_file = os.path.join(tempfile.gettempdir(), "ffuf_out.json")
            rc, _, _ = run_tool(
                ["ffuf", "-u", f"https://{base_host}/FUZZ", "-w", wordlist, "-o", out_file, "-of", "json", "-s"],
                timeout=300,
            )
            if rc == 0 and os.path.isfile(out_file):
                try:
                    import asyncio as _asyncio
                    import json
                    def _read_json():
                        with open(out_file) as f:
                            return json.load(f)
                    data = await _asyncio.to_thread(_read_json)
                    for result in data.get("results", []):
                        url = result.get("url", "")
                        if url:
                            ctx.add_asset(Asset(value=url, asset_type="discovered_path", source="ffuf", metadata={"status": result.get("status")}))
                except Exception:
                    pass