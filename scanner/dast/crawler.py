# scanner/dast/crawler.py
# AGGRESSIVE CRAWLER — Deep crawling, JS endpoint mining, API discovery,
# hidden path probing, form extraction, parameter discovery, and JuiceShop paths

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
import httpx

logger = logging.getLogger(__name__)

# Expanded hidden paths including JuiceShop-specific endpoints
COMMON_HIDDEN_PATHS = [
    # Admin panels
    "/admin", "/admin/login", "/admin/index.php", "/administrator",
    "/admin/dashboard", "/admin/users", "/admin/settings",
    "/wp-admin", "/wp-login.php", "/wp-json/wp/v2/users",
    # Auth
    "/login", "/signin", "/signup", "/register", "/logout",
    "/forgot", "/reset", "/password", "/change-password",
    "/2fa", "/2fa/setup", "/2fa/validate",
    # API
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql",
    "/api/admin", "/api/users", "/api/user", "/api/user/1",
    "/api/products", "/api/product", "/api/search",
    "/api/basket", "/api/basket/1", "/api/basket/1/coupon",
    "/api/complaints", "/api/challenges", "/api/data erasure",
    "/api/security-question", "/api/security-answer",
    "/api/track-result", "/api/address-selection",
    "/api/payment", "/api/recycle", "/api/file-server",
    "/api/error-reporting", "/api/user/whoami",
    "/api/user/reset-password", "/api/user/change-password",
    "/api/product-reviews", "/api/product-reviews/1",
    "/api/quantity", "/api/deluxe-membership",
    "/api/user/1", "/api/users/1",
    # Sensitive files
    "/.env", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.htaccess", "/server-status", "/server-info",
    # Spring Boot / Actuator
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/configprops",
    "/actuator/beans", "/actuator/info", "/actuator/metrics",
    "/actuator/loggers", "/actuator/threaddump",
    "/actuator/heapdump", "/actuator/trace",
    # Debug/dev
    "/debug", "/console", "/trace", "/info", "/status",
    "/phpinfo.php", "/info.php", "/test",
    # User endpoints
    "/user", "/users", "/profile", "/account", "/dashboard",
    "/panel", "/manage", "/management", "/upload", "/uploads", "/files",
    "/search", "/find", "/query",
    # JuiceShop-specific
    "/ftp", "/ftp/quarantine", "/ftp/coupons_2013.md.bak",
    "/encryptionkeys", "/encryptionkeys/default",
    "/score-board", "/administration",
    "/redirect", "/profile", "/profile/change-password",
    "/b2b/v2/orders", "/b2b/v2/supply",
    "/rest/admin", "/rest/user", "/rest/products",
    # vulnweb-specific (Acunetix test site)
    "/AJAX", "/AJAX/infoartist", "/AJAX/infocategory",
    "/AUCTION", "/AUCTION/item", "/AUCTION/category",
    "/product", "/product/1", "/product/2", "/product/3",
    "/user", "/user/1", "/user/2",
    "/api", "/api/user", "/api/user/1", "/api/user/2",
    "/api/product", "/api/product/1",
    "/login", "/login.php",
    "/search", "/search.php",
    "/listproducts", "/listproducts.php",
    "/showimage", "/showimage.php",
    "/adduser", "/adduser.php",
    "/cart", "/cart.php",
    "/checkout", "/checkout.php",
    "/forum", "/forum.php",
    "/guestbook", "/guestbook.php",
    "/index", "/index.php",
    "/style", "/style.css",
    "/WebGoat", "/WebGoat/login", "/WebGoat/start",
    # Swagger/API docs
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger-ui.html", "/swagger-resources", "/v2/api-docs",
    # Health/metrics
    "/metrics", "/health", "/status", "/ping", "/version",
    # Common paths
    "/v1", "/v2", "/v3",
    "/internal", "/private", "/secret",
    "/config", "/settings", "/setup",
    "/backup", "/db", "/database",
    "/phpmyadmin", "/pma",
    "/web.config", "/config.php",
    # OAuth
    "/oauth", "/oauth/authorize", "/oauth/token",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    # Websocket
    "/ws", "/websocket", "/socket.io",
    # Other
    "/sitemap", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/elmah.axd", "/trace.axd",
]

BLOCKED_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp4", ".mp3", ".avi", ".mov", ".wav", ".ogg",
    ".pyc", ".class", ".exe", ".dll", ".so",
    ".min.js",
}


class Crawler:
    def __init__(self, base_url: str, max_pages: int = 300, max_depth: int = 6):
        self.base_url  = base_url.rstrip("/")
        self.base_host = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited   = set()
        self.endpoints = set()
        self.forms     = []
        self.api_endpoints = set()

    async def crawl(self, client: httpx.AsyncClient):
        """Main entry point. Returns (list[str], list[dict]) — endpoints and forms."""
        try:
            await self._crawl_page(client, self.base_url, depth=0)
            await self._probe_hidden_paths(client)
            await self._parse_robots_and_sitemap(client)
            await self._discover_api_endpoints(client)
            await self._probe_common_api_patterns(client)
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
            res = await client.get(url, timeout=15)
        except Exception as e:
            logger.debug(f"[CRAWL ERR] {url}: {e}")
            return

        self.endpoints.add(url)

        ct = res.headers.get("content-type", "")
        if "text/html" not in ct and "application/json" not in ct:
            # Still mine JSON for API endpoints
            if "application/json" in ct:
                self._mine_json_api(res.text, url)
            return

        if "text/html" in ct:
            soup = BeautifulSoup(res.text, "html.parser")

            # Meta refresh redirect
            for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
                content = meta.get("content", "")
                m = re.search(r"url=(.+)", content, re.I)
                if m:
                    target = self._normalize(urljoin(url, m.group(1).strip("'\"")))
                    if self._is_same_domain(target):
                        self.endpoints.add(target)

            self._extract_forms(soup, url)
            await self._extract_js_endpoints(client, soup, url)

            # Extract links from all tags with href/src/action
            tasks = []
            for tag in soup.find_all("a", href=True):
                full = self._normalize(urljoin(url, tag["href"].strip()))
                if full not in self.visited and self._is_same_domain(full) and self._is_valid(full):
                    tasks.append(self._crawl_page(client, full, depth + 1))

            # Also follow link tags, script srcs, iframe srcs
            for tag in soup.find_all(["link", "iframe", "frame", "embed"], src=True):
                full = self._normalize(urljoin(url, tag["src"].strip()))
                if self._is_same_domain(full) and self._is_valid(full):
                    self.endpoints.add(full)

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action") or page_url)
            action = self._normalize(action)
            method = form.get("method", "get").upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded").lower()

            inputs = {}
            for inp in form.find_all(["input", "textarea", "select", "button"]):
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
                res = await client.get(js_url, timeout=15)
                self._mine_js(res.text)
                # Also mine sourcemaps
                sm_url = js_url + ".map"
                sm_res = await client.get(sm_url, timeout=15)
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
        """Extract API endpoints and paths from JavaScript source."""
        patterns = [
            # API path strings
            r'''["'](/(?:api|v\d+|graphql|auth|user|admin|search|data|endpoint|rest|b2b)[a-zA-Z0-9/_\-\.?=&]*)["']''',
            # fetch("...")
            r'''fetch\s*\(\s*["']([^"'\s]+)["']''',
            # axios.get("..."), axios.post("..."), etc.
            r'''axios\.\w+\s*\(\s*["']([^"'\s]+)["']''',
            # $.get("..."), $.post("..."), $.ajax({url:"..."})
            r'''\$\.(?:get|post|ajax)\s*\(\s*["']([^"'\s]+)["']''',
            # XMLHttpRequest .open("GET", "...")
            r'''\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"'\s]+)["']''',
            # url: "...", href: "...", src: "..."
            r'''(?:url|href|src|action|endpoint|path|route)\s*:\s*["']([^"'\s]+)["']''',
            # Template literals with paths
            r'''`(/(?:api|v\d+|rest|admin|user|search)[a-zA-Z0-9/_\-]*)`''',
            # Angular/Vue router paths
            r'''path:\s*["']([^"'\s]+)["']''',
            # Component paths
            r'''component:\s*["']([^"'\s]+)["']''',
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

    def _mine_json_api(self, text: str, source_url: str):
        """Extract API endpoints from JSON responses."""
        try:
            import json
            data = json.loads(text)
            if isinstance(data, dict):
                # Look for URLs in JSON values
                for key, value in data.items():
                    if isinstance(value, str) and value.startswith("/"):
                        full = urljoin(self.base_url, value)
                        if self._is_same_domain(full):
                            self.endpoints.add(full)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict) and "id" in item:
                                # REST collection — add individual item URLs
                                item_url = f"{source_url}/{item['id']}"
                                self.endpoints.add(item_url)
        except Exception:
            pass

    async def _probe_hidden_paths(self, client: httpx.AsyncClient):
        """Probe for hidden paths that aren't linked from any page."""
        async def probe(path: str):
            url = self.base_url + path
            try:
                r = await client.get(url, timeout=15)
                if r.status_code not in (404, 410, 400):
                    self.endpoints.add(url)
                    logger.debug(f"[PROBE] {url} -> {r.status_code}")
            except Exception:
                pass

        # Batch probe with concurrency limit
        sem = asyncio.Semaphore(20)
        async def limited_probe(path):
            async with sem:
                await probe(path)

        await asyncio.gather(
            *[limited_probe(p) for p in COMMON_HIDDEN_PATHS],
            return_exceptions=True,
        )

    async def _parse_robots_and_sitemap(self, client: httpx.AsyncClient):
        """Parse robots.txt and sitemap.xml for additional endpoints."""
        for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
            try:
                r = await client.get(self.base_url + path, timeout=15)
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

    async def _discover_api_endpoints(self, client: httpx.AsyncClient):
        """Try common API documentation endpoints."""
        api_doc_paths = [
            "/swagger-ui.html", "/swagger-resources", "/v2/api-docs",
            "/openapi.json", "/swagger.json", "/api-docs",
            "/.well-known/openapi", "/graphql", "/graphiql",
            "/api/swagger", "/api/docs", "/api/openapi",
        ]
        for path in api_doc_paths:
            try:
                r = await client.get(self.base_url + path, timeout=15)
                if r.status_code == 200:
                    self.endpoints.add(self.base_url + path)
                    # Parse OpenAPI/Swagger JSON
                    if "json" in r.headers.get("content-type", ""):
                        try:
                            import json
                            spec = json.loads(r.text)
                            for path_item in spec.get("paths", {}).keys():
                                full = urljoin(self.base_url, path_item)
                                if self._is_same_domain(full):
                                    self.endpoints.add(full)
                        except Exception:
                            pass
            except Exception:
                pass

    async def _probe_common_api_patterns(self, client: httpx.AsyncClient):
        """Probe common REST API patterns based on discovered endpoints."""
        # If we found /api/users, also try /api/users/1, /api/users/admin, etc.
        api_bases = set()
        for ep in list(self.endpoints):
            parsed = urlparse(ep)
            path = parsed.path
            # Find API base paths
            if re.match(r'^/api(/v\d+)?/\w+$', path):
                api_bases.add(ep)

        for base in api_bases:
            for suffix in ["/1", "/2", "/admin", "/0", "/me", "/current"]:
                url = base.rstrip("/") + suffix
                if url not in self.endpoints:
                    try:
                        r = await client.get(url, timeout=15)
                        if r.status_code not in (404, 410, 400):
                            self.endpoints.add(url)
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
            clean_path = p.path.rstrip("/") or "/"
            return urlunparse((p.scheme, p.netloc, clean_path, p.params, p.query, ""))
        except Exception:
            return url
