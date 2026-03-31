# scanner/crawler.py

import logging
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup
from scanner.js_parser import JSParser

class Crawler:
    def __init__(self, base_url, max_pages=50, max_depth=3):
        self.base_url = base_url
        self.visited = set()
        self.endpoints = set()
        self.forms = []
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.depth_map = {}

        self.js_parser = JSParser()

    # -----------------------
    # FILTER USELESS FILES
    # -----------------------
    def is_valid(self, url):
        blocked_ext = [".jpg", ".png", ".css", ".svg", ".woff", ".ico", ".pdf"]
        return not any(url.lower().endswith(ext) for ext in blocked_ext)

    def is_internal(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    # -----------------------
    # JS PARSING
    # -----------------------
    async def extract_js(self, client, soup, current_url):
        js_endpoints = set()
        scripts = soup.find_all("script", src=True)

        for script in scripts:
            js_url = urljoin(self.base_url, script["src"])

            try:
                logging.info(f"[JS] Fetching: {js_url}")

                res = await client.get(js_url, timeout=10)

                found = self.js_parser.extract_endpoints(
                    res.text, self.base_url
                )

                if found:
                    logging.info(f"[JS] Found {len(found)} endpoints")

                js_endpoints.update(found)

            except Exception as e:
                logging.error(f"[JS ERROR] {e}")

        return js_endpoints

    # -----------------------
    # MAIN CRAWL LOOP
    # -----------------------
    async def crawl(self, client, url=None, depth=0):
        if url is None:
            url = self.base_url

        # LIMITS
        if (
            url in self.visited or
            len(self.visited) >= self.max_pages or
            depth > self.max_depth or
            not self.is_valid(url)
        ):
            return self.endpoints, self.forms

        self.visited.add(url)
        self.depth_map[url] = depth

        logging.info(f"[CRAWL] Visiting ({depth}): {url}")

        try:
            res = await client.get(url, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")

            # ADD CURRENT URL
            self.endpoints.add(url)

            # -----------------------
            # JS DISCOVERY
            # -----------------------
            js_endpoints = await self.extract_js(client, soup, url)

            for ep in js_endpoints:
                if self.is_internal(ep) and self.is_valid(ep):
                    self.endpoints.add(ep)

            # -----------------------
            # COMMON HIDDEN PATHS
            # -----------------------
            common_paths = [
                "/api/",
                "/api/v1/",
                "/admin/",
                "/login.php",
                "/search.php",
                "/dashboard/",
                "/user/"
            ]

            for path in common_paths:
                self.endpoints.add(urljoin(self.base_url, path))

            # -----------------------
            # LINK DISCOVERY
            # -----------------------
            for link in soup.find_all("a", href=True):
                full = urljoin(self.base_url, link["href"])

                if self.is_internal(full) and self.is_valid(full):
                    await self.crawl(client, full, depth + 1)

            # -----------------------
            # FORM DISCOVERY
            # -----------------------
            for form in soup.find_all("form"):
                action = form.get("action") or url
                method = form.get("method", "get").lower()

                inputs = list(set([
                    inp.get("name")
                    for inp in form.find_all(["input", "textarea"])
                    if inp.get("name")
                ]))

                form_obj = {
                    "url": urljoin(self.base_url, action),
                    "method": method,
                    "inputs": inputs
                }

                if form_obj not in self.forms:
                    self.forms.append(form_obj)

        except Exception as e:
            logging.error(f"[CRAWL ERROR] {url}: {e}")

        return self.endpoints, self.forms