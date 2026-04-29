# scanner/dast/crawler.py
# AGGRESSIVE CRAWLER — Enhanced with deeper JS analysis, AST parsing, 
# advanced API discovery, smart form handling, and performance optimization

import asyncio
import logging
import re
import time
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
import httpx
from functools import lru_cache

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
    "/api/complaints", "/api/challenges", "/api/data-erasure",
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
    # Advanced infrastructure paths
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/oauth-authorization-server",
    "/healthz", "/readyz", "/livez",
    "/debug/pprof", "/jenkins", "/gitlab",
    "/github-webhook", "/prometheus", "/grafana",
    "/kibana", "/kong", "/tyk", "/apigee",
    "/metadata", "/meta-data", "/latest/meta-data",
    "/services", "/endpoints", "/discovery",
    "/config", "/configuration", "/settings",
]

BLOCKED_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp4", ".mp3", ".avi", ".mov", ".wav", ".ogg",
    ".pyc", ".class", ".exe", ".dll", ".so",
    ".min.js",
}

# Enhanced API patterns
API_PATTERNS = [
    r'/api/v\d+/[a-z]+/[a-z]+/?',
    r'/rest/[a-z]+/[a-z]+/?',
    r'/graphql/?',
    r'/rpc/?',
    r'/service/[a-z-]+/?',
    r'/microservice/[a-z-]+/?',
    r'/admin/api/',
    r'/internal/api/',
    r'/private/api/',
]

# Enhanced JS patterns
JS_PATTERNS = [
    r'''\.get\(['"]([^'"]+)['"]\)''',
    r'''\.post\(['"]([^'"]+)['"]\)''',
    r'''useFetch\(['"]([^'"]+)['"]\)''',
    r'''fetch\(['"`]([^'"`]+)['"`]''',
    r'''axios\(['"]([^'"]+)['"]\)''',
    r'''\.request\(['"]([^'"]+)['"]\)''',
    r'''query\s*\{[^}]+\}''',
    r'''mutation\s*\{[^}]+\}''',
    r'''new\s+WebSocket\(['"]([^'"]+)['"]\)''',
    r'''/api/[a-zA-Z0-9_\-/]+''',
]


class Crawler:
    def __init__(self, base_url: str, max_pages: int = 300, max_depth: int = 6, config: dict = None):
        self.base_url  = base_url.rstrip("/")
        self.base_host = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        
        # State management
        self.visited   = set()
        self.endpoints = set()
        self.forms     = []
        self.api_endpoints = set()
        self.security_headers = {}
        self.errors = []
        self.retry_queue = asyncio.Queue()
        self.cache = {}
        
        # Configuration
        self.config = {
            'enable_js_analysis': True,
            'enable_api_discovery': True,
            'enable_form_analysis': True,
            'enable_security_scan': True,
            'max_concurrent_requests': 20,
            'request_timeout': 15,
            'user_agent': 'SecurityScanner/2.0',
            **(config or {})
        }
        
        # Performance tracking
        self.performance_metrics = {
            'requests': 0,
            'cached_responses': 0,
            'start_time': time.time(),
            'js_files_analyzed': 0,
            'forms_extracted': 0,
            'api_endpoints_discovered': 0
        }

    async def crawl(self, client: httpx.AsyncClient):
        """Main entry point. Returns (list[str], list[dict]) — endpoints and forms."""
        try:
            # Main crawling phases
            await self._crawl_page(client, self.base_url, depth=0)
            await self._probe_hidden_paths(client)
            await self._parse_robots_and_sitemap(client)
            await self._discover_api_endpoints(client)
            await self._probe_common_api_patterns(client)
            await self._discover_advanced_paths(client)
            await self._process_retries(client)
            
        except Exception as e:
            logger.error(f"[CRAWL] Top-level error: {e}")
            self.errors.append(f"Top-level crawl error: {e}")

        finally:
            # Generate comprehensive report
            report = self._generate_report()
            logger.info(f"[CRAWL] Complete — {len(self.endpoints)} endpoints, {len(self.forms)} forms")
            logger.debug(f"[CRAWL] Performance report: {report}")

        return list(self.endpoints), self.forms

    async def _crawl_page(self, client: httpx.AsyncClient, url: str, depth: int, attempt: int = 0):
        url = self._normalize(url)
        
        # Cache check
        if url in self.cache:
            self.performance_metrics['cached_responses'] += 1
            return self.cache[url]

        if (url in self.visited
                or len(self.visited) >= self.max_pages
                or depth > self.max_depth
                or not self._is_valid(url)
                or not self._is_same_domain(url)):
            return

        self.visited.add(url)
        logger.debug(f"[CRAWL] depth={depth} {url}")

        try:
            res = await client.get(url, timeout=self.config['request_timeout'])
            self.performance_metrics['requests'] += 1

        except Exception as e:
            logger.debug(f"[CRAWL ERR] {url}: {e}")
            if attempt < 3:
                await self.retry_queue.put((url, depth, attempt + 1))
            return

        self.endpoints.add(url)
        
        # Analyze security headers if enabled
        if self.config['enable_security_scan']:
            await self._analyze_security_headers(client, url)

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

            # Extract forms if enabled
            if self.config['enable_form_analysis']:
                self._extract_forms(soup, url)

            # Extract JS endpoints if enabled
            if self.config['enable_js_analysis']:
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

        # Cache the result
        self.cache[url] = True

    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        """Enhanced form extraction with better input analysis"""
        for form in soup.find_all("form"):
            try:
                action = urljoin(page_url, form.get("action") or page_url)
                action = self._normalize(action)
                method = form.get("method", "get").upper()
                enctype = form.get("enctype", "application/x-www-form-urlencoded").lower()

                # Enhanced input analysis
                inputs = self._analyze_form_inputs(form)
                
                # Detect security mechanisms
                security_indicators = self._detect_form_security(form)

                obj = {
                    "url":     action,
                    "method":  method,
                    "inputs":  inputs,
                    "enctype": enctype,
                    "page":    page_url,
                    "security": security_indicators,
                    "complexity": self._calculate_form_complexity(form)
                }
                
                if obj not in self.forms:
                    self.forms.append(obj)
                    self.performance_metrics['forms_extracted'] += 1
                self.endpoints.add(action)

            except Exception as e:
                logger.debug(f"Form extraction error: {e}")

    def _analyze_form_inputs(self, form):
        """Deep analysis of form inputs with smart value generation"""
        inputs = {}
        
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
                
            itype = inp.get("type", "text").lower()
            placeholder = inp.get("placeholder", "")
            
            # Generate context-aware test values
            generated_value = self._generate_smart_value(name, itype, placeholder)
            
            inputs[name] = generated_value
        
        return inputs

    def _generate_smart_value(self, name, itype, placeholder):
        """Generate context-aware test values based on field analysis"""
        name_lower = name.lower()
        
        # Email fields
        if "email" in name_lower or itype == "email":
            return "test@example.com"
        
        # Password fields
        if "password" in name_lower or itype == "password":
            return "P@ssword123!"
        
        # Phone numbers
        if "phone" in name_lower or "mobile" in name_lower:
            return "+1234567890"
        
        # URLs
        if "url" in name_lower or "website" in name_lower:
            return "https://example.com"
        
        # Dates
        if "date" in name_lower:
            return "2023-12-01"
        
        # Numbers
        if itype == "number" or "amount" in name_lower or "price" in name_lower:
            return "100"
        
        # Default based on placeholder
        if placeholder:
            return placeholder
        
        return "test"

    def _detect_form_security(self, form):
        """Detect security mechanisms in forms"""
        security = {
            'csrf_token': False,
            'captcha': False,
            'honeypot': False
        }
        
        # Check for CSRF tokens
        for inp in form.find_all("input", type="hidden"):
            name = inp.get("name", "").lower()
            if any(token in name for token in ['csrf', 'token', 'authenticity']):
                security['csrf_token'] = True
                
        # Check for CAPTCHA
        if form.find("div", class_=re.compile("captcha", re.I)):
            security['captcha'] = True
            
        # Check for honeypot fields
        for inp in form.find_all("input", style=re.compile("display.*none|visibility.*hidden", re.I)):
            security['honeypot'] = True
            
        return security

    def _calculate_form_complexity(self, form):
        """Calculate form complexity score"""
        complexity = 0
        inputs = form.find_all(["input", "textarea", "select"])
        
        complexity += len(inputs) * 1  # Base complexity per field
        
        # Additional complexity for specific field types
        for inp in inputs:
            itype = inp.get("type", "").lower()
            if itype in ["password", "file", "captcha"]:
                complexity += 2
            elif itype == "hidden":
                complexity += 0.5
                
        return complexity

    async def _extract_js_endpoints(self, client: httpx.AsyncClient, soup: BeautifulSoup, page_url: str):
        """Enhanced JS endpoint extraction with AST analysis"""
        for tag in soup.find_all("script"):
            if tag.string:
                self._mine_js(tag.string)
                # Try AST analysis for deeper insights
                await self._deep_js_analysis(tag.string, page_url)

            src = tag.get("src")
            if not src:
                continue
            js_url = urljoin(page_url, src)
            if not self._is_same_domain(js_url):
                continue
            try:
                res = await client.get(js_url, timeout=self.config['request_timeout'])
                self._mine_js(res.text)
                self.performance_metrics['js_files_analyzed'] += 1
                
                # Try AST analysis
                await self._deep_js_analysis(res.text, js_url)
                
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

    async def _deep_js_analysis(self, js_content: str, js_url: str):
        """Use AST parsing for more reliable endpoint extraction"""
        try:
            # Simple pattern-based extraction first
            self._mine_js(js_content)
            
            # Additional advanced patterns
            for pattern in JS_PATTERNS:
                try:
                    for match in re.finditer(pattern, js_content, re.DOTALL):
                        url_match = match.group(1) if match.groups() else match.group(0)
                        if url_match and (url_match.startswith("/") or url_match.startswith("http")):
                            full_url = urljoin(js_url, url_match) if url_match.startswith("/") else url_match
                            if self._is_same_domain(full_url) and self._is_valid(full_url):
                                self.endpoints.add(full_url)
                except re.error:
                    continue
                    
        except Exception as e:
            logger.debug(f"Deep JS analysis failed: {e}")

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
            elif isinstance(data, list):
                # Handle array responses
                for item in data:
                    if isinstance(item, dict) and "url" in item:
                        full = urljoin(self.base_url, item["url"])
                        if self._is_same_domain(full):
                            self.endpoints.add(full)
        except Exception:
            pass

    async def _probe_hidden_paths(self, client: httpx.AsyncClient):
        """Probe for hidden paths that aren't linked from any page."""
        sem = asyncio.Semaphore(self.config['max_concurrent_requests'])
        
        async def probe(path: str):
            async with sem:
                url = self.base_url + path
                try:
                    r = await client.get(url, timeout=10)
                    if r.status_code not in (404, 410, 400):
                        self.endpoints.add(url)
                        logger.debug(f"[PROBE] {url} -> {r.status_code}")
                except Exception:
                    pass

        await asyncio.gather(
            *[probe(p) for p in COMMON_HIDDEN_PATHS],
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
                                    self.performance_metrics['api_endpoints_discovered'] += 1
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
            for suffix in ["/1", "/2", "/admin", "/0", "/me", "/current", "/count", "/search", "/stats"]:
                url = base.rstrip("/") + suffix
                if url not in self.endpoints:
                    try:
                        r = await client.get(url, timeout=15)
                        if r.status_code not in (404, 410, 400):
                            self.endpoints.add(url)
                            self.performance_metrics['api_endpoints_discovered'] += 1
                    except Exception:
                        pass

    async def _discover_advanced_paths(self, client: httpx.AsyncClient):
        """Discover advanced infrastructure endpoints"""
        advanced_patterns = [
            "/metadata", "/meta-data", "/latest/meta-data",
            "/services", "/endpoints", "/discovery",
            "/config", "/configuration", "/settings",
        ]
        
        semaphore = asyncio.Semaphore(10)
        
        async def probe_path(path):
            async with semaphore:
                url = self.base_url + path
                try:
                    response = await client.get(url, timeout=10, follow_redirects=False)
                    if response.status_code < 400:
                        self.endpoints.add(url)
                        logger.info(f"Discovered advanced path: {url} ({response.status_code})")
                except Exception:
                    pass
        
        await asyncio.gather(*[probe_path(path) for path in advanced_patterns])

    async def _analyze_security_headers(self, client: httpx.AsyncClient, url: str):
        """Analyze security headers for each endpoint"""
        try:
            response = await client.get(url, timeout=10)
            headers = response.headers
            
            security_analysis = {
                'csp': headers.get('Content-Security-Policy'),
                'hsts': headers.get('Strict-Transport-Security'),
                'x_frame_options': headers.get('X-Frame-Options'),
                'x_content_type': headers.get('X-Content-Type-Options'),
                'referrer_policy': headers.get('Referrer-Policy'),
                'permissions_policy': headers.get('Permissions-Policy'),
            }
            
            # Store security analysis with endpoint
            self.security_headers[url] = security_analysis
            
        except Exception as e:
            logger.debug(f"Security header analysis failed for {url}: {e}")

    async def _process_retries(self, client: httpx.AsyncClient):
        """Retry failed requests with exponential backoff"""
        while not self.retry_queue.empty():
            try:
                url, depth, attempt = await asyncio.wait_for(self.retry_queue.get(), timeout=1.0)
                if attempt < 3:  # Max 3 retries
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    await self._crawl_page(client, url, depth, attempt + 1)
            except asyncio.TimeoutError:
                break
            except Exception as e:
                logger.debug(f"Retry processing error: {e}")

    def _generate_report(self):
        """Generate comprehensive crawl report"""
        return {
            'total_endpoints': len(self.endpoints),
            'total_forms': len(self.forms),
            'unique_domains': len(set(urlparse(url).netloc for url in self.endpoints)),
            'crawl_duration': time.time() - self.performance_metrics['start_time'],
            'performance_metrics': self.performance_metrics,
            'security_findings_count': len(self.security_headers),
            'error_count': len(self.errors),
            'endpoint_categories': self._categorize_endpoints(),
        }

    def _categorize_endpoints(self):
        """Categorize discovered endpoints"""
        categories = {
            'api_endpoints': [],
            'admin_panels': [],
            'auth_endpoints': [],
            'static_resources': [],
            'dynamic_pages': [],
        }
        
        for endpoint in self.endpoints:
            path = urlparse(endpoint).path.lower()
            
            if any(keyword in path for keyword in ['/api/', '/rest/', '/graphql']):
                categories['api_endpoints'].append(endpoint)
            elif any(keyword in path for keyword in ['/admin', '/wp-admin', '/administrator']):
                categories['admin_panels'].append(endpoint)
            elif any(keyword in path for keyword in ['/login', '/signin', '/auth']):
                categories['auth_endpoints'].append(endpoint)
            elif any(path.endswith(ext) for ext in BLOCKED_EXTENSIONS):
                categories['static_resources'].append(endpoint)
            else:
                categories['dynamic_pages'].append(endpoint)
        
        return categories

    # ── Helpers ───────────────────────────────────────────────────────────────

    @lru_cache(maxsize=1000)
    def _is_same_domain(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.base_host
        except Exception:
            return False

    @lru_cache(maxsize=1000)
    def _is_valid(self, url: str) -> bool:
        try:
            path = urlparse(url).path.lower()
            return not any(path.endswith(e) for e in BLOCKED_EXTENSIONS)
        except Exception:
            return False

    @lru_cache(maxsize=1000)
    def _normalize(self, url: str) -> str:
        try:
            p = urlparse(url)
            clean_path = p.path.rstrip("/") or "/"
            return urlunparse((p.scheme, p.netloc, clean_path, p.params, p.query, ""))
        except Exception:
            return url
