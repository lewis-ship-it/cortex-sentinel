# scanner/dast/active_scanner.py
#
# AGGRESSIVE ACTIVE SCANNER — Comprehensive vulnerability detection pipeline
# Phases: WAF/Tech detection -> Deep Crawl -> Hidden Param Discovery -> Module Execution
#          -> Header Injection -> Sensitive Files -> Security Headers -> GraphQL -> OAST
# Modules: Injection, ClientSide, Infra, Access, XXE, NoSQL, API Abuse

import asyncio
import logging
import random
import re
from urllib.parse import urlparse, urlunparse, quote as url_quote

import httpx

from scanner.dast.crawler import Crawler
from scanner.dast.param_engine import ParamEngine
from scanner.dast.context_engine import ContextEngine
from scanner.dast.waf_detector import WAFDetector
from scanner.dast.graphql_engine import check_graphql_introspection
from task_queue.redis_client import log_event
from scanner.detector import SQLI_ERROR_SIGNATURES

try:
    from scanner.dast.oast import OASTManager
    HAS_OAST = True
except ImportError:
    HAS_OAST = False

try:
    from intelligence.usage_tracker import UsageTracker
    HAS_TRACKER = True
except ImportError:
    HAS_TRACKER = False

logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Version/17.4.1 Safari/605.1.15",
]

BASE_DELAY   = 0.08
JITTER_RANGE = 0.22
BURST_EVERY  = 10
BURST_PAUSE  = (0.8, 1.6)

SENSITIVE_FILES = [
    ("/.env",              ["DB_PASSWORD","SECRET_KEY","AWS_","API_KEY","MONGO","POSTGRES"]),
    ("/.env.local",        ["DB_PASSWORD","SECRET_KEY"]),
    ("/.env.production",   ["DB_PASSWORD","SECRET_KEY"]),
    ("/.env.development",  ["DB_PASSWORD","SECRET_KEY"]),
    ("/.git/HEAD",         ["ref:","refs/heads"]),
    ("/.git/config",       ["[core]","repositoryformatversion"]),
    ("/web.config",        ["connectionString","appSettings"]),
    ("/config.php",        ["password","database","$db"]),
    ("/phpinfo.php",       ["PHP Version","phpinfo()"]),
    ("/server-status",     ["Apache Server Status"]),
    ("/actuator/env",      ["systemProperties","applicationConfig"]),
    ("/actuator/mappings", ["dispatcherServlet"]),
    ("/actuator/heapdump", [""]),
    ("/backup.sql",        ["INSERT INTO","CREATE TABLE"]),
    ("/dump.sql",          ["INSERT INTO","CREATE TABLE"]),
    ("/id_rsa",            ["-----BEGIN","PRIVATE KEY"]),
    ("/composer.json",     ["require","autoload"]),
    ("/package.json",      ["dependencies","scripts"]),
    ("/crossdomain.xml",   ["cross-domain-policy","allow-access-from"]),
    ("/clientaccesspolicy.xml", ["access-policy","allow-from"]),
    ("/.htaccess",         ["RewriteEngine","AuthType"]),
    ("/wp-config.php",     ["DB_PASSWORD","DB_NAME"]),
    ("/database.yml",      ["adapter","password"]),
    ("/settings.py",       ["SECRET_KEY","DATABASE"]),
    ("/config.json",       ["password","secret","key"]),
    ("/.svn/entries",      ["dir","svn"]),
    ("/.DS_Store",         ["Bud1","ds"]),
    ("/encryptionkeys",    ["key","secret","encrypt"]),
    ("/encryptionkeys/default", ["key","secret"]),
]

LISTING_MARKERS = ["Index of /","Directory listing","Parent Directory"]

# Header injection payloads
HEADER_INJECTION_TESTS = [
    ("X-Forwarded-For", "127.0.0.1", "IP bypass may grant admin access"),
    ("X-Original-URL", "/admin", "URL rewrite bypass may access admin paths"),
    ("X-Rewrite-URL", "/admin", "URL rewrite bypass may access admin paths"),
    ("X-Custom-IP-Authorization", "127.0.0.1", "IP-based auth bypass"),
    ("X-Forwarded-Host", "localhost", "Host header injection"),
    ("X-Host", "localhost", "Host header injection"),
    ("X-HTTP-Method-Override", "PUT", "HTTP method override bypass"),
    ("X-Method-Override", "DELETE", "HTTP method override bypass"),
    ("X-Forwarded-Proto", "https", "Protocol downgrade bypass"),
    ("X-Real-IP", "127.0.0.1", "IP spoofing for auth bypass"),
    ("True-Client-IP", "127.0.0.1", "IP spoofing for auth bypass"),
    ("X-Client-IP", "127.0.0.1", "IP spoofing for auth bypass"),
    ("X-Remote-IP", "127.0.0.1", "IP spoofing for auth bypass"),
    ("X-Remote-Addr", "127.0.0.1", "IP spoofing for auth bypass"),
    ("X-Originating-IP", "127.0.0.1", "IP spoofing for auth bypass"),
    ("Forwarded", "for=127.0.0.1", "Forwarded header bypass"),
]


class ActiveScanner:
    MAX_REQUESTS = 8000
    CONCURRENCY  = 15

    def __init__(self, job_id: str = None, budget: float = 2.00):
        self.param_engine   = ParamEngine()
        self.context_engine = ContextEngine()
        self.waf_detector   = WAFDetector()
        self.semaphore      = asyncio.Semaphore(self.CONCURRENCY)
        self.oast           = OASTManager() if HAS_OAST else None
        self.marker         = "CTX88"
        self.job_id         = job_id
        self.max_budget     = budget
        self.tracker        = UsageTracker(max_budget_usd=budget) if HAS_TRACKER else None

        # Per-scan state reset in scan()
        self.findings       = []
        self._seen_findings = set()
        self._last_req_ts   = {}
        self.canary_map     = {}
        self.request_count  = 0
        self.target_tech    = ["Generic"]
        self.waf_name       = None
        self.target_url     = ""

    # ─────────────────────────────────────────────────────────────────────────
    # THROTTLE
    # ─────────────────────────────────────────────────────────────────────────
    async def _human_delay(self, url: str) -> None:
        if self.request_count > 0 and self.request_count % BURST_EVERY == 0:
            await asyncio.sleep(random.uniform(*BURST_PAUSE))
            return
        host    = urlparse(url).netloc
        now     = asyncio.get_event_loop().time()
        elapsed = now - self._last_Req_ts.get(host, 0.0)
        needed  = BASE_DELAY + random.uniform(0, JITTER_RANGE)
        if elapsed < needed:
            await asyncio.sleep(needed - elapsed)
        self._last_req_ts[host] = asyncio.get_event_loop().time()

    # ─────────────────────────────────────────────────────────────────────────
    # SAFE REQUEST
    # ─────────────────────────────────────────────────────────────────────────
    async def _req(self, client: httpx.AsyncClient, method: str, url: str, **kwargs):
        if self.request_count >= self.MAX_REQUESTS:
            return None
        if self.tracker and not self.tracker.is_active:
            log_event(self.job_id, "CRITICAL", "Budget exceeded — scan halted.")
            return None

        async with self.semaphore:
            self.request_count += 1
            if self.tracker:
                self.tracker.log_request()
            await self._human_delay(url)

            headers = kwargs.pop("headers", {})
            headers["User-Agent"] = random.choice(USER_AGENTS)
            headers["Accept-Language"] = "en-US,en;q=0.9"
            if self.target_url:
                headers["Referer"] = self.target_url

            for attempt in range(3):
                try:
                    res = await client.request(method, url, headers=headers, **kwargs)
                    if res.status_code in (429, 503):
                        wait = (attempt + 1) * 5
                        log_event(self.job_id, "WAF", f"Rate limited — backing off {wait}s")
                        await asyncio.sleep(wait)
                        continue
                    if res.text:
                        self._check_second_order(res.text, url)
                    return res
                except (httpx.ConnectError, httpx.ReadTimeout):
                    if attempt == 2:
                        return None
                    await asyncio.sleep(1)
                except Exception as e:
                    logger.debug(f"[REQ ERR] {url}: {e}")
                    return None
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # SECOND-ORDER DETECTION
    # ─────────────────────────────────────────────────────────────────────────
    def _check_second_order(self, text: str, url: str) -> None:
        for canary, info in self.canary_map.items():
            if canary in text:
                fid = f"SO::{canary}::{url}"
                if fid not in self._seen_findings:
                    self._add_finding({
                        "type": "Second-Order Vulnerability",
                        "subtype": "Stored Input Reflection",
                        "url": url, "parameter": info.get("param","unknown"),
                        "payload": canary, "severity": "High", "confidence": 0.95,
                        "evidence": f"Canary injected at {info['url']} found at {url}",
                        "description": "Stored input rendered elsewhere — Stored XSS risk.",
                    })
                    self._seen_findings.add(fid)

    # ─────────────────────────────────────────────────────────────────────────
    # CONTEXT
    # ─────────────────────────────────────────────────────────────────────────
    async def _get_context(self, client, url: str, param: str) -> str:
        test_url = self.param_engine.inject_payload(url, param, self.marker)
        res = await self._req(client, "GET", test_url)
        if res and res.text:
            return self.context_engine.detect_context(res.text, self.marker)
        return "unknown"

    # ─────────────────────────────────────────────────────────────────────────
    # AUTH
    # ─────────────────────────────────────────────────────────────────────────
    async def _handle_auth(self, client, auth_config: dict) -> None:
        atype = auth_config.get("type")
        if atype == "login":
            try:
                await client.post(
                    auth_config["login_url"],
                    data={"username": auth_config["username"], "password": auth_config["password"]},
                    timeout=10,
                )
            except Exception as e:
                logger.warning(f"[AUTH] Login failed: {e}")
        elif atype == "cookie":
            for k, v in auth_config.get("cookies", {}).items():
                client.cookies.set(k, v)
        elif atype == "bearer":
            client.headers["Authorization"] = f"Bearer {auth_config['token']}"

    # ─────────────────────────────────────────────────────────────────────────
    # WAF + TECH DETECTION
    # ─────────────────────────────────────────────────────────────────────────
    async def _detect_waf_and_tech(self, client, base_url: str) -> None:
        self.waf_name = await self.waf_detector.detect(client, base_url)
        if self.waf_name and self.waf_name != "Generic":
            logger.warning(f"[WAF] Detected: {self.waf_name}")
            log_event(self.job_id, "WAF", f"WAF detected: {self.waf_name}")

        try:
            res = await self._req(client, "GET", base_url)
            if res:
                self.target_tech = self._fingerprint(res)
                logger.info(f"[SCAN] Tech stack: {self.target_tech}")
                log_event(self.job_id, "SCAN", f"Tech fingerprint: {', '.join(self.target_tech)}")
        except Exception:
            pass

    def _fingerprint(self, res: httpx.Response) -> list:
        x_powered = res.headers.get("X-Powered-By","").lower()
        server    = res.headers.get("Server","").lower()
        cookies   = str(res.cookies).lower()
        body      = res.text.lower()
        tech = []
        if "php" in x_powered or ".php" in str(res.url):
            tech.append("PHP")
        if "express" in x_powered or "node" in server:
            tech.append("Node.js")
        if "csrf" in cookies or "django" in body:
            tech.append("Django")
        if "flask" in cookies:
            tech.append("Flask")
        if "asp.net" in x_powered or "iis" in server:
            tech.append("ASP.NET")
        if "wp-content" in body or "wp-json" in body:
            tech.append("WordPress")
        if "laravel" in cookies or "laravel" in body:
            tech.append("Laravel")
        if "angular" in body:
            tech.append("Angular")
        if "react" in body or "__next" in body:
            tech.append("React")
        if "vue" in body:
            tech.append("Vue")
        if "juice" in body or "juiceshop" in body:
            tech.append("JuiceShop")
        return tech or ["Generic"]

    # ─────────────────────────────────────────────────────────────────────────
    # MAIN SCAN ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────────
    async def scan(self, base_url: str, auth_config: dict = None, job_id: str = None) -> list:
        # Reset per-scan state
        self.findings       = []
        self._seen_findings = set()
        self.request_count  = 0
        self._last_req_ts   = {}
        self.canary_map     = {}
        self.waf_name       = None
        self.target_tech    = ["Generic"]
        self.job_id         = job_id
        self.target_url     = base_url

        logger.info(f"[SCAN] Starting: {base_url}")
        log_event(self.job_id, "SCAN", f"Starting scan: {base_url}")

        # OAST setup
        oast_active = False
        if HAS_OAST and self.oast:
            try:
                await self.oast.register()
                self.oast_domain = self.oast.domain
                oast_active = True
                log_event(self.job_id, "OAST", f"OAST monitor active: {self.oast_domain}")
            except Exception as e:
                logger.warning(f"[OAST] Setup failed: {e}")

        audit_semaphore = asyncio.SSemaphore(8)

        async with httpx.AsyncClient(timeout=20, verify=False, follow_redirects=True) as client:
            if auth_config:
                await self._handle_auth(client, auth_config)

            # Phase 0+: WAF + Tech fingerprint
            await self._detect_waf_and_tech(client, base_url)

            # Phase 2: Deep Crawl
            crawler = Crawler(base_url, max_pages=300, max_depth=6)
            endpoints, forms = await crawler.crawl(client)
            log_event(self.job_id, "CRAWL", f"Found {len(endpoints)} endpoints, {len(forms)} forms")

            # Phase 2b: Hidden parameter discovery on key endpoints
            hidden_urls = []
            for url in endpoints[:50]:  # Top 50 endpoints
                if urlparse(url).query:
                    hidden_urls.extend(self.param_engine.get_hidden_param_urls(url)[:10])
            for h_url in hidden_urls:
                endpoints.append(h_url)
            log_event(self.job_id, "CRAWL", f"Added {len(hidden_urls)} hidden-param URLs")

            # Phase 3: Recon (parallel)
            await asyncio.gather(
                self._check_security_headers(client, base_url),
                self._check_sensitive_files(client, base_url),
                self._run_graphql_check(client, base_url),
                self._test_header_injection(client, base_url),
                self._test_http_methods(client, base_url),
                return_exceptions=True,
            )

            # Phase 4: Module execution on all endpoints
            tasks = []
            for url in endpoints:
                async def _audit_url(u=url):
                    async with audit_semaphore:
                        await self._run_all_modules(client, u)
                tasks.append(_audit_url())
            for form in forms:
                async def _audit_form(f=form):
                    async with audit_semaphore:
                        await self._run_form_modules(client, f)
                tasks.append(_audit_form())
            await asyncio.gather(*tasks, return_exceptions=True)

            # Phase 5: Path-based IDOR testing
            await self._test_path_idor(client, endpoints)

            # Phase 6: OAST polling
            if oast_active:
                await asyncio.sleep(3)
                interactions = await self.oast.poll_interactions()
                for hit in interactions:
                    self._add_finding({
                        "type": "Blind Out-of-Band Vulnerability",
                        "subtype": hit.get("protocol","DNS/HTTP"),
                        "url": base_url, "severity": "Critical", "confidence": 0.98,
                        "evidence": f"OAST hit from {hit.get('remote_ip')} via {hit.get('protocol')}",
                        "description": "Server made external request to OAST domain — Blind SSRF/RCE confirmed.",
                    })

        log_event(self.job_id, "SCAN", f"Complete: {len(self.findings)} findings, {self.request_count} requests")
        return self.findings

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE ORCHESTRATION
    # ─────────────────────────────────────────────────────────────────────────
    async def _run_all_modules(self, client, url: str) -> None:
        params = self.param_engine.extract_params(url)
        if not params:
            # Try adding common params to discover injection points
            for variant in self.param_engine.add_param_variants(url)[:5]:
                params = self.param_engine.extract_params(variant)
                if params:
                    url = variant
                    break

        from scanner.dast.modules.injection import InjectionModule
        from scanner.dast.modules.client_side import ClientSideModule
        from scanner.dast.modules.infra import InfraModule
        from scanner.dast.modules.access import AccessModule

        mods = [InjectionModule(self), ClientSideModule(self), InfraModule(self), AccessModule(self)]

        if params:
            await asyncio.gather(*(m.run(client, url, params) for m in mods), return_exceptions=True)

        # Always test path-based injection for REST-style URLs
        await self._test_path_injection(client, url)

    async def _run_form_modules(self, client, form: dict) -> None:
        from scanner.dast.modules.injection import InjectionModule
        from scanner.dast.modules.client_side import ClientSideModule
        await asyncio.gather(
            InjectionModule(self).test_form(client, form),
            ClientSideModule(self).test_form(client, form),
            return_exceptions=True,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # PATH-BASED INJECTION (REST-style URLs like /product/1, /api/users/5)
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_path_injection(self, client, url: str) -> None:
        """Inject payloads into path segments for REST-style endpoints."""
        from scanner.dast.payloads import LFI_PAYLOADS

        parsed = urlparse(url)
        segments = parsed.path.split("/")
        path_idx = []
        for i, seg in enumerate(segments):
            if seg.isdigit() or re.match(r'^[a-f0-9]{8,}$', seg):
                path_idx.append(i)

        if not path_idx:
            return

        for idx in path_idx:
            original = segments[idx]

            # SQLi in path
            for payload in ["1'", "1' OR '1'='1", "1'--", "1 UNION SELECT 1,2,3--", "0"]:
                new_segs = segments[:]
                new_segs[idx] = url_quote(payload, safe='')
                test_path = "/".join(new_segs)
                test_url = urlunparse((parsed.scheme, parsed.netloc, test_path,
                                       parsed.params, parsed.query, parsed.fragment))
                res = await self._req(client, "GET", test_url)
                if not res:
                    continue
                body = res.text
                body_lower = body.lower()
                found_sig = None
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig.lower() in body_lower:
                        found_sig = sig
                        break
                    try:
                        if re.search(sig, body, re.IGNORECASE | re.DOTALL):
                            found_sig = sig
                            break
                    except re.error:
                        continue
                if found_sig:
                    self._add_finding({
                        "type": "SQL Injection", "subtype": "Path-Based Error",
                        "url": test_url, "parameter": f"path[{idx}]",
                        "payload": payload, "severity": "Critical", "confidence": 0.90,
                        "evidence": f"DB error in path segment: '{found_sig}'",
                        "description": f"Path segment '{original}' is injectable — unsanitised input reaches the DB.",
                    })
                    return

            # LFI in path
            for payload in LFI_PAYLOADS[:8]:
                new_segs = segments[:]
                new_segs[idx] = url_quote(payload, safe='')
                test_path = "/".join(new_segs)
                test_url = urlunparse((parsed.scheme, parsed.netloc, test_path,
                                       parsed.params, parsed.query, parsed.fragment))
                res = await self._req(client, "GET", test_url)
                if not res:
                    continue
                for ind in ["root:x:", "root:0:0", "[boot loader]", "PHP Version", "phpinfo()"]:
                    if ind in res.text:
                        self._add_finding({
                            "type": "Local File Inclusion (LFI)", "subtype": "Path-Based",
                            "url": test_url, "parameter": f"path[{idx}]",
                            "payload": payload, "severity": "Critical", "confidence": 0.90,
                            "evidence": f"File marker '{ind}' in response",
                            "description": f"Path segment '{original}' allows file inclusion.",
                        })
                        return

            # XSS in path
            for payload in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]:
                new_segs = segments[:]
                new_segs[idx] = url_quote(payload, safe='')
                test_path = "/".join(new_segs)
                test_url = urlunparse((parsed.scheme, parsed.netloc, test_path,
                                       parsed.params, parsed.query, parsed.fragment))
                res = await self._req(client, "GET", test_url)
                if res and payload in res.text:
                    self._add_finding({
                        "type": "Cross-Site Scripting (XSS)", "subtype": "Path-Based Reflected",
                        "url": test_url, "parameter": f"path[{idx}]",
                        "payload": payload, "severity": "High", "confidence": 0.85,
                        "evidence": "Payload reflected in path segment",
                        "description": f"Path segment '{original}' reflects unsanitised input.",
                    })
                    return

    # ─────────────────────────────────────────────────────────────────────────
    # HEADER INJECTION / AUTH BYPASS
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_header_injection(self, client, base_url: str) -> None:
        """Test for auth bypass via header injection."""
        # Get baseline response
        baseline = await self._req(client, "GET", base_url)
        if not baseline:
            return
        baseline_len = len(baseline.text)
        baseline_status = baseline.status_code

        for header_name, header_value, description in HEADER_INJECTION_TESTS:
            res = await self._req(client, "GET", base_url, headers={header_name: header_value})
            if not res:
                continue

            # Check if the header changed the response significantly
            if res.status_code != baseline_status:
                if res.status_code == 200 and baseline_status in (401, 403):
                    self._add_finding({
                        "type": "Authentication Bypass via Header",
                        "subtype": f"{header_name}: {header_value}",
                        "url": base_url, "parameter": header_name,
                        "payload": header_value,
                        "severity": "Critical", "confidence": 0.95,
                        "evidence": f"Status changed from {baseline_status} to {res.status_code} with {header_name}",
                        "description": description,
                    })
            elif res.status_code == 200 and abs(len(res.text) - baseline_len) > 500:
                # Same status but very different content — might have bypassed
                self._add_finding({
                    "type": "Authentication Bypass via Header",
                    "subtype": f"{header_name}: {header_value}",
                    "url": base_url, "parameter": header_name,
                    "payload": header_value,
                    "severity": "High", "confidence": 0.90,
                    "evidence": f"Response size changed from {baseline_len} to {len(res.text)} with {header_name}",
                    "description": description,
                })

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP METHOD TESTING
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_http_method_tampering(self, client, base_url: str) -> None:
        """Test for dangerous HTTP methods and method-based auth bypass."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Test common API endpoints with different methods
        test_paths = ["/", "/api", "/api/users", "/admin"]
        for path in test_paths:
            url = base + path
            for method in ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]:
                try:
                    res = await self._req(client, method, url)
                    if not res:
                        continue
                    if method == "OPTIONS":
                        allow = res.headers.get("Allow", "")
                        if allow and any(m in allow for m in ["PUT", "DELETE", "PATCH"]):
                            self._add_finding({
                                "type": "Dangerous HTTP Methods Allowed",
                                "subtype": f"OPTIONS on {path}",
                                "url": url, "parameter": "HTTP Method",
                                "payload": "OPTIONS",
                                "severity": "Medium", "confidence": 0.90,
                                "evidence": f"Allow: {allow}",
                                "description": f"Server allows dangerous methods: {allow}",
                            })
                    elif method in ("PUT", "DELETE", "PATCH"):
                        if res.status_code not in (404, 405, 403, 501):
                            self._add_finding({
                                "type": "HTTP Method Tampering",
                                "subtype": f"{method} on {path}",
                                "url": url, "parameter": "HTTP Method",
                                "payload": method,
                                "severity": "High", "confidence": 0.80,
                                "evidence": f"{method} returned {res.status_code}",
                                "description": f"Server accepted {method} on {path} — may allow unauthorized modifications.",
                            })
                except Exception:
                    continue

    # ─────────────────────────────────────────────────────────────────────────
    # PATH-BASED IDOR
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_path_idor(self, client, endpoints: list) -> None:
        """Test for IDOR in URL path segments (e.g., /api/users/1)."""
        idor_patterns = [
            (r'/api/users/(\d+)', "User IDOR"),
            (r'/api/basket/(\d+)', "Basket IDOR"),
            (r'/api/product-reviews/(\d+)', "Review IDOR"),
            (r'/api/orders/(\d+)', "Order IDOR"),
            (r'/api/invoices/(\d+)', "Invoice IDOR"),
            (r'/user/(\d+)', "User IDOR"),
            (r'/profile/(\d+)', "Profile IDOR"),
        ]

        for url in endpoints:
            for pattern, label in idor_patterns:
                m = re.search(pattern, url)
                if not m:
                    continue
                current_id = int(m.group(1))
                baseline = await self._req(client, "GET", url)
                if not baseline or baseline.status_code != 200:
                    continue
                baseline_len = len(baseline.text)

                for test_id in [current_id - 1, current_id + 1, 1, 2, 0]:
                    if test_id < 0 or test_id == current_id:
                        continue
                    test_url = re.sub(pattern, lambda _: f'/api/users/{test_id}' if 'users' in pattern else f'/api/basket/{test_id}' if 'basket' in pattern else f'/api/product-reviews/{test_id}' if 'product-reviews' in pattern else f'/api/orders/{test_id}' if 'orders' in pattern else f'/api/invoices/{test_id}' if 'invoices' in pattern else f'/user/{test_id}' if 'user' in pattern.split('/')[-2] else f'/profile/{test_id}', url)
                    # Simpler approach: just replace the number
                    test_url = re.sub(r'/(\d+)(?=[/?]|$)', f'/{test_id}', url, count=1)
                    res = await self._req(client, "GET", test_url)
                    if not res or res.status_code != 200:
                        continue
                    diff = abs(len(res.text) - baseline_len)
                    if diff > 100 and len(res.text) > 200:
                        self._add_finding({
                            "type": "Insecure Direct Object Reference (IDOR)",
                            "subtype": f"Path-Based: {label}",
                            "url": test_url, "parameter": "path_id",
                            "payload": str(test_id),
                            "severity": "Critical", "confidence": 0.85,
                            "evidence": f"ID={test_id} returned 200 with {len(res.text)}B (baseline={baseline_len}B)",
                            "description": f"Path segment allows accessing other objects — {label}.",
                        })
                        break

    # ─────────────────────────────────────────────────────────────────────────
    # GRAPHQL, SECURITY HEADERS, SENSITIVE FILES
    # ─────────────────────────────────────────────────────────────────────────
    async def _run_graphql_check(self, client, base_url: str) -> None:
        result = await check_graphql_introspection(client, base_url)
        if result:
            self._add_finding({
                "type": result["type"], "url": result["url"], "parameter": "N/A",
                "payload": "GraphQL Introspection Query", "severity": result["severity"],
                "confidence": 1.0, "evidence": "Full __schema returned",
                "description": result["description"],
            })

    async def _check_security_headers(self, client, base_url: str) -> None:
        res = await self._req(client, "GET", base_url)
        if not res:
            return
        h = {k.lower(): v for k, v in res.headers.items()}
        REQUIRED = {
            "content-security-policy":   ("Medium","No CSP — XSS executes freely."),
            "x-frame-options":           ("Medium","No X-Frame-Options — clickjacking possible."),
            "x-content-type-options":    ("Low",   "No nosniff header."),
            "strict-transport-security": ("Medium","No HSTS — HTTP downgrade possible."),
            "referrer-policy":           ("Low",   "No Referrer-Policy."),
            "permissions-policy":        ("Low",   "No Permissions-Policy."),
        }
        for header, (sev, desc) in REQUIRED.items():
            if header not in h:
                self._add_finding({
                    "type":"Missing Security Header","subtype":header.title(),
                    "url":base_url,"severity":sev,"confidence":1.0,
                    "evidence":f"'{header}' absent","description":desc,
                })
        # CORS check
        cors = await self._req(client, "GET", base_url, headers={"Origin":"https://evil.com"})
        if cors:
            acao = cors.headers.get("access-control-allow-origin","")
            acac = cors.headers.get("access-control-allow-credentials","").lower()
            if acao == "*" and acac == "true":
                self._add_finding({
                    "type":"CORS Misconfiguration","subtype":"Wildcard+Credentials",
                    "url":base_url,"severity":"Critical","confidence":1.0,
                    "evidence":f"ACAO={acao} ACAC={acac}",
                    "description":"Any origin can make authenticated cross-origin requests.",
                })
            elif acao == "https://evil.com":
                self._add_finding({
                    "type":"CORS Misconfiguration","subtype":"Reflected Origin",
                    "url":base_url,"severity":"High","confidence":0.95,
                    "evidence":f"Reflected: {acao}",
                    "description":"Server mirrors Origin header — all origins allowed.",
                })

    async def _check_sensitive_files(self, client, base_url: str) -> None:
        base = base_url.rstrip("/")
        for path, indicators in SENSITIVE_FILES:
            url = base + path
            res = await self._req(client, "GET", url)
            if not (res and res.status_code == 200):
                continue
            if not indicators:
                # Empty indicators = any 200 is a finding
                self._add_finding({
                    "type":"Sensitive File Exposed","subtype":path,
                    "url":url,"severity":"Critical","confidence":0.90,
                    "evidence":f"File accessible (HTTP 200, {len(res.text)}B)",
                    "description":f"File {path} is publicly accessible.",
                })
                continue
            for ind in indicators:
                if ind.lower() in res.text.lower():
                    self._add_finding({
                        "type":"Sensitive File Exposed","subtype":path,
                        "url":url,"severity":"Critical","confidence":0.97,
                        "evidence":f"Indicator '{ind}' found",
                        "description":f"File {path} is publicly accessible.",
                    })
                    break
        for d in ["/uploads/","/backup/","/logs/","/files/","/tmp/","/ftp/"]:
            url = base + d
            res = await self._req(client, "GET", url)
            if res and res.status_code == 200 and any(m in res.text for m in LISTING_MARKERS):
                self._add_finding({
                    "type":"Directory Listing Enabled","subtype":d,
                    "url":url,"severity":"Medium","confidence":0.99,
                    "evidence":"Directory index returned",
                    "description":f"Directory {d} exposes file names.",
                })

    # ─────────────────────────────────────────────────────────────────────────
    # FINALIZE
    # ─────────────────────────────────────────────────────────────────────────
    async def finalize_and_report(self) -> dict:
        if not self.tracker:
            return {}
        try:
            metrics = self.tracker.get_final_metrics()
        except Exception:
            metrics = {}
        log_event(self.job_id, "BILLING", f"Scan cost: ${metrics.get('estimated_cost_usd', 0):.4f}")
        return metrics

    # ─────────────────────────────────────────────────────────────────────────
    # DEDUPLICATION
    # ─────────────────────────────────────────────────────────────────────────
    def _add_finding(self, f: dict) -> None:
        key = "::".join([f.get("type",""), f.get("url",""),
                         f.get("parameter",""), f.get("payload","")[:30]])
        if key in self._seen_findings:
            return
        self._seen_findings.add(key)
        self.findings.append(f)
        log_event(self.job_id, "VULN",
                  f"{f.get('severity')} {f.get('type')} at {f.get('url')}")
        logger.info(f"[FINDING] {f.get('severity'):8s} | {f.get('type')} | {f.get('url')}")


# ─────────────────────────────────────────────────────────────────────────────
# AI FALSE-POSITIVE TAGGER
# Tags every finding with FP likelihood instead of dropping any.
# All findings are kept — the UI decides what to highlight.
# ─────────────────────────────────────────────────────────────────────────────
    async def tag_false_positives(findings: list, brain) -> list:
        """Tag each finding with ai_confidence and fp_likelihood. Never drops findings."""
        for f in findings:
            # OAST-verified or very high confidence → unlikely FP
            if "OAST" in f.get("type","") or f.get("confidence",0) > 0.98:
                f["ai_confidence"]  = 1.0
                f["ai_explanation"] = "Verified via out-of-band interaction."
                f["fp_likelihood"]  = "unlikely"
                continue
            try:
                result = await brain.validate_finding(f)
                conf = result.get("confidence", 0)
                f["ai_confidence"]  = conf
                f["ai_explanation"] = result.get("reason","")
                if conf >= 0.85:
                    f["fp_likelihood"] = "unlikely"
                elif conf >= 0.60:
                    f["fp_likelihood"] = "possible"
                else:
                    f["fp_likelihood"] = "likely"
            except Exception as e:
                logger.warning(f"[AI TAGGER] Error: {e}")
                f["ai_confidence"] = 0.5
                f["fp_likelihood"] = "possible"
        return findings

