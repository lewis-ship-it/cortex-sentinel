# scanner/smart_crawler.py

import httpx
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class SmartCrawler:
    """
    Lightweight async crawler used by crawl_workers.py.
    Stays within the same domain and avoids binary/asset URLs.
    """

    BLOCKED_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
        ".css", ".woff", ".woff2", ".ttf", ".otf",
        ".ico", ".pdf", ".zip", ".mp4", ".mp3"
    }

    def __init__(self, max_pages=50):
        self.max_pages = max_pages

    def _is_valid(self, url):
        from urllib.parse import urlparse as _parse
        path = _parse(url).path.lower()
        return not any(path.endswith(ext) for ext in self.BLOCKED_EXTENSIONS)

    def _same_domain(self, url, base_url):
        return urlparse(url).netloc == urlparse(base_url).netloc

    async def crawl(self, base_url):
        """
        Crawl base_url and return a list of discovered same-domain endpoints.
        Creates its own httpx client internally so it can be called
        directly from the worker without passing a client.
        """
        visited   = set()
        endpoints = set()
        queue     = [base_url]

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=10
        ) as client:
            while queue and len(visited) < self.max_pages:
                url = queue.pop(0)

                if url in visited or not self._is_valid(url):
                    continue

                visited.add(url)
                endpoints.add(url)

                try:
                    res  = await client.get(url)
                    soup = BeautifulSoup(res.text, "html.parser")

                    for tag in soup.find_all("a", href=True):
                        full = urljoin(base_url, tag["href"])
                        if (
                            full not in visited
                            and self._same_domain(full, base_url)
                            and self._is_valid(full)
                        ):
                            queue.append(full)

                except Exception as e:
                    logging.debug(f"[SMART CRAWL] {url}: {e}")

        return list(endpoints)