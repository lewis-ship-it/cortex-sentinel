# scanner/dast/crawler.py
# FIX: Regex patterns rewritten — backtick in character class caused SyntaxError.
# FIX: crawl() now always returns (endpoints, forms) tuple.
# IMPROVED: Added form action normalisation, JS sourcemap mining, meta refresh detection.

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
import httpx

logger = logging.getLogger(__name__)

COMMON_HIDDEN_PATHS = [
    "/admin", "/admin/login", "/admin/index.php", "/administrator",
    "/wp-admin", "/wp-login.php", "/wp-json/wp/v2/users",
    "/login", "/signin", "/signup", "/register",
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql",
    "/.env", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.htaccess", "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/debug", "/console", "/trace",
    "/user", "/users", "/profile", "/account", "/dashboard",
    "/panel", "/manage", "/management", "/upload", "/uploads", "/files",
    "/search", "/find", "/query", "/forgot", "/reset", "/password",
    "/phpmyadmin", "/pma", "/backup", "/config.php", "/web.config",
    "/phpinfo.php", "/info.php",
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json", "/api-docs",
    "/metrics", "/health", "/status", "/ping",
    "/v1", "/v2", "/v3",
    "/internal", "/private", "/secret",
    "/config", "/settings", "/setup",
]

BLOCKED_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp4", ".mp3", ".avi", ".mov", ".wav", ".ogg",
    ".pyc", ".class", ".exe", ".dll", ".so",
    ".min.js",  # minified JS — not useful for endpoint mining
}


class Crawler:
    def __init__(self, base_url: str, max_pages: int = 150, max_depth: int = 5):
        self.base_url  = base_url.rstrip("/")
        self.base_host = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited   = set()
        self.endpoints = set()
        self.forms     = []

    async def crawl(self, client: httpx.AsyncClient):
        """
        Main entry point. Returns (list[str], list[dict]) — endpoints and forms.
        FIX: Always returns a tuple regardless of errors.
        """
        try:
            await self._crawl_page(client, self.base_url, depth=0)
            await self._probe_hidden_paths(client)
            await self._parse_robots_and_sitemap(client)
        except Exception as e:
            logger.error(f"[CRAWL] Top-level error: {e}")

        logger.info(f"[CRAWL] Complete — {len(self.endpoints)} endpoints, {len(self.forms)} forms")
        return list(self.endpoints), self.forms

    async def _crawl_page(self, client: httpx.AsyncClient, url: str, depth: int):
        url = self._normalize(url)
        if (url in self.visited
                or len(self.visited) >= self.max_pages
                or depth > self.max_depth
                or not self._is_valid(url)
                or not self._is_same_domain(url)):
            return

        self.visited.add(url)
        logger.debug(f"[CRAWL] depth={depth} {url}")

        try:
            res = await client.get(url, timeout=12)
        except Exception as e:
            logger.debug(f"[CRAWL ERR] {url}: {e}")
            return

        self.endpoints.add(url)

        ct = res.headers.get("content-type", "")
        if "text/html" not in ct:
            return

        soup = BeautifulSoup(res.text, "html.parser")

        # Meta refresh redirect — follow it
        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
            content = meta.get("content", "")
            m = re.search(r"url=(.+)", content, re.I)
            if m:
                target = self._normalize(urljoin(url, m.group(1).strip("'\"")))
                if self._is_same_domain(target):
                    self.endpoints.add(target)

        self._extract_forms(soup, url)
        await self._extract_js_endpoints(client, soup, url)

        tasks = []
        for tag in soup.find_all("a", href=True):
            full = self._normalize(urljoin(url, tag["href"].strip()))
            if full not in self.visited and self._is_same_domain(full) and self._is_valid(full):
                tasks.append(self._crawl_page(client, full, depth + 1))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action") or page_url)
            action = self._normalize(action)
            method = form.get("method", "get").upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded").lower()

            inputs = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                itype = inp.get("type", "text").lower()
                if itype == "email":
                    inputs[name] = "test@example.com"
                elif itype == "password":
                    inputs[name] = "P@ssword123!"
                elif itype in ("hidden", "submit", "button", "image", "reset"):
                    inputs[name] = inp.get("value", "1")
                elif itype == "checkbox":
                    inputs[name] = inp.get("value", "on")
                elif itype == "number":
                    inputs[name] = inp.get("value", "1")
                else:
                    inputs[name] = inp.get("value", "test")

            obj = {
                "url":     action,
                "method":  method,
                "inputs":  inputs,
                "enctype": enctype,
                "page":    page_url,
            }
            if obj not in self.forms:
                self.forms.append(obj)
            self.endpoints.add(action)

    async def _extract_js_endpoints(self, client: httpx.AsyncClient, soup: BeautifulSoup, page_url: str):
        for tag in soup.find_all("script"):
            if tag.string:
                self._mine_js(tag.string)

            src = tag.get("src")
            if not src:
                continue
            js_url = urljoin(page_url, src)
            if not self._is_same_domain(js_url):
                continue
            try:
                res = await client.get(js_url, timeout=8)
                self._mine_js(res.text)
                # Also mine sourcemaps if referenced
                sm_url = js_url + ".map"
                sm_res = await client.get(sm_url, timeout=5)
                if sm_res.status_code == 200 and "sources" in sm_res.text:
                    import json as _json
                    try:
                        sm = _json.loads(sm_res.text)
                        for src_path in sm.get("sources", []):
                            full = urljoin(self.base_url, src_path)
                            if self._is_same_domain(full):
                                self.endpoints.add(full)
                    except Exception:
                        pass
            except Exception:
                pass

    def _mine_js(self, text: str):
        """
        FIX: Regex patterns rewritten without backtick inside character classes
        (Python does not support backtick in regex char classes in all versions).
        """
        patterns = [
            # API path strings: "/api/...", "/v1/...", etc.
            r'''["'](/(?:api|v\d+|graphql|auth|user|admin|search|data|endpoint)[a-zA-Z0-9/_\-\.?=&]*)["']''',
            # fetch("...")
            r'''fetch\s*\(\s*["']([^"'\s]+)["']''',
            # axios.get("..."), axios.post("..."), etc.
            r'''axios\.\w+\s*\(\s*["']([^"'\s]+)["']''',
            # $.get("..."), $.post("..."), $.ajax({url:"..."})
            r'''\$\.(?:get|post|ajax)\s*\(\s*["']([^"'\s]+)["']''',
            # XMLHttpRequest .open("GET", "...")
            r'''\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"'\s]+)["']''',
            # url: "...", href: "...", src: "..."
            r'''(?:url|href|src|action|endpoint)\s*:\s*["']([^"'\s]+)["']''',
        ]
        for pat in patterns:
            try:
                for m in re.findall(pat, text):
                    if m.startswith("/") and len(m) > 1:
                        full = urljoin(self.base_url, m)
                        if self._is_same_domain(full) and self._is_valid(full):
                            self.endpoints.add(full)
                    elif m.startswith("http") and self._is_same_domain(m):
                        self.endpoints.add(m)
            except re.error:
                continue

    async def _probe_hidden_paths(self, client: httpx.AsyncClient):
        async def probe(path: str):
            url = self.base_url + path
            try:
                r = await client.get(url, timeout=6)
                if r.status_code not in (404, 410, 400):
                    self.endpoints.add(url)
                    logger.debug(f"[PROBE] {url} → {r.status_code}")
            except Exception:
                pass

        await asyncio.gather(
            *[probe(p) for p in COMMON_HIDDEN_PATHS],
            return_exceptions=True,
        )

    async def _parse_robots_and_sitemap(self, client: httpx.AsyncClient):
        for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
            try:
                r = await client.get(self.base_url + path, timeout=6)
                if r.status_code != 200:
                    continue
                for line in r.text.splitlines():
                    line = line.strip()
                    if ":" not in line:
                        continue
                    key, _, val = line.partition(":")
                    val = val.strip()
                    if val.startswith("/"):
                        self.endpoints.add(self.base_url + val)
                    elif val.startswith("http") and self._is_same_domain(val):
                        self.endpoints.add(val)
            except Exception:
                pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_same_domain(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.base_host
        except Exception:
            return False

    def _is_valid(self, url: str) -> bool:
        try:
            path = urlparse(url).path.lower()
            return not any(path.endswith(e) for e in BLOCKED_EXTENSIONS)
        except Exception:
            return False

    def _normalize(self, url: str) -> str:
        try:
            p = urlparse(url)
            # Strip fragment, normalise trailing slash on path
            clean_path = p.path.rstrip("/") or "/"
            return urlunparse((p.scheme, p.netloc, clean_path, p.params, p.query, ""))
        except Exception:
            return url
