# scanner/dast/crawler.py
import asyncio, logging, re
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
import httpx

logger = logging.getLogger(__name__)

COMMON_HIDDEN_PATHS = [
    "/admin", "/admin/login", "/administrator", "/login", "/signin",
    "/signup", "/register", "/api", "/api/v1", "/api/v2", "/graphql",
    "/wp-admin", "/wp-login.php", "/.env", "/.git/HEAD",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/server-status",
    "/actuator/health", "/actuator/env", "/debug", "/console",
    "/user", "/users", "/profile", "/account", "/dashboard",
    "/panel", "/manage", "/upload", "/uploads", "/files",
    "/search", "/find", "/query", "/forgot", "/reset",
    "/phpmyadmin", "/backup", "/config.php", "/web.config",
]

BLOCKED_EXTENSIONS = {
    ".jpg",".jpeg",".png",".gif",".webp",".svg",".ico",
    ".css",".woff",".woff2",".ttf",".otf",".eot",
    ".pdf",".zip",".tar",".gz",".rar",
    ".mp4",".mp3",".avi",".wav",".pyc",".class",".exe",
}


class Crawler:
    def __init__(self, base_url: str, max_pages: int = 120, max_depth: int = 4):
        self.base_url  = base_url.rstrip("/")
        self.base_host = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited   = set()
        self.endpoints = set()
        self.forms     = []

    async def crawl(self, client: httpx.AsyncClient):
        await self._crawl_page(client, self.base_url, 0)
        await self._probe_hidden_paths(client)
        await self._parse_robots(client)
        logger.info(f"[CRAWL] {len(self.endpoints)} endpoints, {len(self.forms)} forms")
        return list(self.endpoints), self.forms

    async def _crawl_page(self, client, url: str, depth: int):
        url = self._normalize(url)
        if (url in self.visited or len(self.visited) >= self.max_pages
                or depth > self.max_depth or not self._is_valid(url)
                or not self._is_same_domain(url)):
            return
        self.visited.add(url)
        logger.debug(f"[CRAWL] d={depth} {url}")
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
        self._extract_forms(soup, url)
        await self._extract_js_endpoints(client, soup, url)
        tasks = []
        for tag in soup.find_all("a", href=True):
            full = self._normalize(urljoin(url, tag["href"].strip()))
            if full not in self.visited and self._is_same_domain(full) and self._is_valid(full):
                tasks.append(self._crawl_page(client, full, depth + 1))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_forms(self, soup, page_url: str):
        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action") or page_url)
            method = form.get("method", "get").upper()
            inputs = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                itype = inp.get("type", "text").lower()
                if itype == "email":     inputs[name] = "test@test.com"
                elif itype == "password": inputs[name] = "password123"
                elif itype in ("hidden", "submit", "button"):
                    inputs[name] = inp.get("value", "1")
                else: inputs[name] = inp.get("value", "test")
            obj = {"url": action, "method": method, "inputs": inputs, "page": page_url}
            if obj not in self.forms:
                self.forms.append(obj)
                self.endpoints.add(action)

    async def _extract_js_endpoints(self, client, soup, page_url: str):
        for tag in soup.find_all("script"):
            if tag.string:
                self._mine_js(tag.string)
            src = tag.get("src")
            if src and self._is_same_domain(urljoin(page_url, src)):
                try:
                    r = await client.get(urljoin(page_url, src), timeout=8)
                    self._mine_js(r.text)
                except Exception:
                    pass

    def _mine_js(self, text: str):
        pats = [
            r'["'`](/(?:api|v\d+|graphql|auth|user|admin|search)[a-zA-Z0-9/_\-\.?=&]*)[`"\']',
            r'fetch\s*\(\s*["'`]([^"'`\s]+)["'`]',
            r'axios\.\w+\s*\(\s*["'`]([^"'`\s]+)["'`]',
        ]
        for pat in pats:
            for m in re.findall(pat, text):
                if m.startswith("/") and len(m) > 1:
                    full = urljoin(self.base_url, m)
                    if self._is_same_domain(full) and self._is_valid(full):
                        self.endpoints.add(full)

    async def _probe_hidden_paths(self, client):
        async def probe(path):
            url = self.base_url + path
            try:
                r = await client.get(url, timeout=6)
                if r.status_code not in (404, 410, 400):
                    self.endpoints.add(url)
            except Exception:
                pass
        await asyncio.gather(*[probe(p) for p in COMMON_HIDDEN_PATHS], return_exceptions=True)

    async def _parse_robots(self, client):
        for path in ["/robots.txt", "/sitemap.xml"]:
            try:
                r = await client.get(self.base_url + path, timeout=6)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        line = line.strip()
                        if ":" in line:
                            parts = line.split(":", 1)
                            val = parts[1].strip()
                            if val.startswith("/"):
                                self.endpoints.add(self.base_url + val)
                            elif val.startswith("http") and self._is_same_domain(val):
                                self.endpoints.add(val)
            except Exception:
                pass

    def _is_same_domain(self, url: str) -> bool:
        try: return urlparse(url).netloc == self.base_host
        except: return False

    def _is_valid(self, url: str) -> bool:
        try:
            p = urlparse(url).path.lower()
            return not any(p.endswith(e) for e in BLOCKED_EXTENSIONS)
        except: return False

    def _normalize(self, url: str) -> str:
        try:
            p = urlparse(url)
            return urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", p.params, p.query, ""))
        except: return url
