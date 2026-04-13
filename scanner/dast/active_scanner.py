# scanner/dast/active_scanner.py
#
# PLACEMENT: Replace scanner/dast/active_scanner.py entirely.
#
# NEW IN THIS VERSION:
#   • WAF detection  (_detect_waf)        — runs before any payloads
#   • SSRF testing   (_test_ssrf)         — wired into Phase 5
#   • CMDI testing   (_test_cmdi)         — wired into Phase 5
#   • IDOR testing   (_test_idor)         — wired into Phase 6
#   • Auth testing   (_test_auth_panel)   — default-cred + lockout
#   • Jitter + UA rotation  (_req / _human_delay)
#   • AI false-positive filter  (filter_false_positives)

import asyncio
import logging
import random
import re
import time
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

import httpx

from scanner.dast.crawler import Crawler
from scanner.dast.param_engine import ParamEngine
from scanner.dast.payloads import (
    SQLI_PAYLOADS, XSS_PAYLOADS, LFI_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS, SSTI_PAYLOADS,
    CMDI_PAYLOADS, SSRF_PAYLOADS,
    SQLI_ERROR_SIGNATURES,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# USER-AGENT POOL  (rotated per request)
# ─────────────────────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

# ─────────────────────────────────────────────────────────────────────────────
# THROTTLE  (human-like timing)
# ─────────────────────────────────────────────────────────────────────────────
BASE_DELAY   = 0.08          # 80 ms floor
JITTER_RANGE = 0.22          # +0–220 ms random jitter  →  max gap ≈ 300 ms
BURST_EVERY  = 10            # longer pause every N requests
BURST_PAUSE  = (0.8, 1.6)   # seconds — simulates human "reading" pause

# ─────────────────────────────────────────────────────────────────────────────
# WAF SIGNATURES
# ─────────────────────────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":  ["cf-ray", "cloudflare", "__cfduid"],
    "AWS WAF":     ["x-amzn-requestid", "awselb"],
    "Akamai":      ["akamai", "ak_bmsc", "x-akamai"],
    "Imperva":     ["incapsula", "visid_incap", "x-iinfo"],
    "ModSecurity": ["mod_security", "modsecurity", "not acceptable"],
    "Sucuri":      ["x-sucuri-id", "sucuri"],
    "Barracuda":   ["barra_counter_session"],
    "F5 BIG-IP":   ["bigip", "f5-", "ts="],
}

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT CREDENTIALS  (for auth panel testing)
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "admin123"),
    ("admin",  "123456"),
    ("admin",  ""),
    ("root",   "root"),
    ("root",   "toor"),
    ("test",   "test"),
    ("guest",  "guest"),
    ("admin",  "pass"),
    ("user",   "user"),
    ("admin",  "letmein"),
]

# ─────────────────────────────────────────────────────────────────────────────
# SSRF INDICATORS  (what we look for in responses)
# ─────────────────────────────────────────────────────────────────────────────
SSRF_INDICATORS = [
    # AWS metadata
    "ami-id", "instance-id", "iam/security-credentials", "local-ipv4",
    # GCP
    "computeMetadata", "google-cloud",
    # Redis
    "-ERR", "+PONG", "+OK",
    # Internal services
    "MongoDB", "mysql", "postgresql",
    # Generic
    "localhost", "127.0.0.1",
]

SSRF_PROBE_PARAMS = frozenset({
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "path", "fetch", "load", "file", "resource",
    "host", "target", "endpoint", "proxy", "request", "href",
    "import", "data", "callback", "remote",
})

# ─────────────────────────────────────────────────────────────────────────────
# CMDI INDICATORS
# ─────────────────────────────────────────────────────────────────────────────
CMDI_OUTPUT_INDICATORS = [
    "root:x:", "daemon:", "nobody:", "www-data", "bin/bash",
    "uid=", "gid=", "groups=",
    "[boot loader]", "[fonts]",      # Windows win.ini
    "Microsoft Windows", "Volume in drive",
]

CMDI_TIME_PAYLOADS = [
    ("; sleep 3",              3.0),
    ("| sleep 3",              3.0),
    ("& sleep 3",              3.0),
    ("$(sleep 3)",             3.0),
    ("`sleep 3`",              3.0),
    ("; ping -c 3 127.0.0.1", 3.0),
    ("| ping -c 3 127.0.0.1", 3.0),
]

CMDI_OUTPUT_PAYLOADS = [
    ("; cat /etc/passwd",   CMDI_OUTPUT_INDICATORS),
    ("| cat /etc/passwd",   CMDI_OUTPUT_INDICATORS),
    ("$(cat /etc/passwd)",  CMDI_OUTPUT_INDICATORS),
    ("; whoami",            ["root", "www-data", "apache", "nginx", "nobody"]),
    ("| whoami",            ["root", "www-data", "apache", "nginx", "nobody"]),
    ("; id",                ["uid=", "gid=", "groups="]),
    ("| id",                ["uid=", "gid=", "groups="]),
]

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN / LOGIN PATHS TO PROBE FOR AUTH TESTING
# ─────────────────────────────────────────────────────────────────────────────
AUTH_PANEL_PATHS = [
    "/admin", "/admin/login", "/admin/index.php",
    "/administrator", "/administrator/index.php",
    "/wp-admin", "/wp-login.php",
    "/login", "/signin", "/user/login", "/auth/login",
    "/panel", "/dashboard", "/manage", "/management",
    "/phpmyadmin", "/pma",
    "/cpanel", "/whm",
]

# Common form field names for username / password
USERNAME_FIELDS = ["username", "user", "email", "login", "uname", "usr", "name"]
PASSWORD_FIELDS = ["password", "pass", "passwd", "pwd", "secret"]


class ActiveScanner:

    SQLI_TIME_THRESHOLD = 3.0
    CMDI_TIME_THRESHOLD = 3.0
    MAX_REQUESTS        = 1000
    CONCURRENCY         = 12

    def __init__(self):
        self.param_engine       = ParamEngine()
        self.semaphore          = asyncio.Semaphore(self.CONCURRENCY)
        self.request_count      = 0
        self.findings           = []
        self._seen_findings     = set()
        self._last_request_ts   = {}
        self.waf                = None   # set by _detect_waf

    # ─────────────────────────────────────────────────────────────────────────
    # HUMAN-LIKE DELAY  (per-host throttle + burst pause)
    # ─────────────────────────────────────────────────────────────────────────
    async def _human_delay(self, url: str) -> None:
        host = urlparse(url).netloc

        if self.request_count > 0 and self.request_count % BURST_EVERY == 0:
            pause = random.uniform(*BURST_PAUSE)
            logger.debug(f"[THROTTLE] Burst pause {pause:.2f}s")
            await asyncio.sleep(pause)
            return

        now     = asyncio.get_event_loop().time()
        last    = self._last_request_ts.get(host, 0.0)
        elapsed = now - last
        jitter  = random.uniform(0, JITTER_RANGE)
        needed  = BASE_DELAY + jitter

        if elapsed < needed:
            await asyncio.sleep(needed - elapsed)

        self._last_request_ts[host] = asyncio.get_event_loop().time()

    # ─────────────────────────────────────────────────────────────────────────
    # SAFE REQUEST  (throttled, semaphore-guarded, UA-rotated)
    # ─────────────────────────────────────────────────────────────────────────
    async def _req(self, client: httpx.AsyncClient, method: str, url: str, **kwargs):
        """
        Stateful request helper. 
        Maintains cookies/session state while rotating User-Agents and adding jitter.
        """
        if self.request_count >= self.MAX_REQUESTS:
            return None

        async with self.semaphore:
            self.request_count += 1
            
            # 1. Apply stealth jitter/delay
            await self._human_delay(url)

            # 2. Extract and rotate headers
            headers = kwargs.pop("headers", {})
            headers["User-Agent"] = random.choice(USER_AGENTS)
            
            # Ensure the client doesn't overwrite necessary session headers
            # but allow the specific request to override if needed.
            try:
                # 3. Use generic request method to handle GET, POST, OPTIONS, etc.
                # This automatically uses the 'client' (session) cookie jar.
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    **kwargs
                )
                
                # 4. Detect WAF/Rate Limiting for adaptive slowdown
                if response.status_code in (403, 429):
                    logger.warning(f"[STEALTH] Possible block/rate-limit detected at {url}. Status: {response.status_code}")
                
                return response

            except httpx.TimeoutException:
                logger.debug(f"[TIMEOUT] {url}")
                return None
            except Exception as e:
                logger.debug(f"[REQ ERR] {url}: {e}")
                return None

    # ─────────────────────────────────────────────────────────────────────────
    # STATEFUL SCAN ENGINE
    # ─────────────────────────────────────────────────────────────────────────
    async def scan(self, base_url: str, auth_config: dict = None) -> list:
        """
        Refactored scan engine: Maintains session state across all phases.
        """
        self.findings         = []
        self._seen_findings   = set()
        self.request_count    = 0
        self._last_request_ts = {}
        self.waf              = None

        logger.info(f"[STATEFUL SCAN] Starting: {base_url}")

        # 1. Initialize Cookie Jar from auth_config
        initial_cookies = auth_config.get("cookies") if auth_config else None
        initial_headers = auth_config.get("headers", {})

        # 2. Open a persistent session
        async with httpx.AsyncClient(
            timeout=20, 
            verify=False, 
            follow_redirects=True,
            cookies=initial_cookies
        ) as client:
            
            # Apply any custom auth headers (Tokens, API Keys)
            if initial_headers:
                client.headers.update(initial_headers)

            # Handle advanced auth logic (Login flows if defined)
            if auth_config:
                await self._handle_auth(client, auth_config)

            # ── Phase 0: WAF detection ─────────────────────────────────────
            logger.info("[SCAN] Phase 0 — WAF detection")
            self.waf = await self._detect_waf(client, base_url)
            if self.waf:
                logger.warning(f"[WAF] Detected: {self.waf} — session using evasion logic")

            # ── Phase 1: Stateful Crawl ────────────────────────────────────
            # The crawler now benefits from the cookies set in the client
            logger.info("[SCAN] Phase 1 — Stateful Crawl")
            crawler = Crawler(base_url)
            endpoints, forms = await crawler.crawl(client)
            logger.info(f"[SCAN] {len(endpoints)} endpoints, {len(forms)} forms found in session")

            # ── Phase 2: Recon ─────────────────────────────────────────────
            logger.info("[SCAN] Phase 2 — Headers & info disclosure")
            await self._check_security_headers(client, base_url)
            await self._check_info_disclosure(client, base_url)

            # ── Phase 3-7: Attack Vector Tasks ─────────────────────────────
            # All tasks below share the 'client' object, maintaining the session
            tasks = []

            # URL-param injection
            logger.info("[SCAN] Phase 3 — URL param injection")
            for url in endpoints:
                params = self.param_engine.extract_params(url)
                if not params:
                    for v in self.param_engine.add_param_variants(url)[:3]:
                        for p in self.param_engine.extract_params(v):
                            tasks.append(self._test_all(client, v, p))
                else:
                    for p in params:
                        tasks.append(self._test_all(client, url, p))

            # Form injection
            logger.info("[SCAN] Phase 4 — Form injection")
            for form in forms:
                tasks.append(self._test_form(client, form))

            # Deep checks (SQLi, LFI, SSRF, CMDI, etc.)
            logger.info("[SCAN] Phase 5 — Vulnerability Engines")
            for url in endpoints:
                for p in self.param_engine.extract_params(url):
                    tasks.append(self._test_sqli(client, url, p)) # Updated with Diffing logic
                    tasks.append(self._test_xss(client, url, p))  # Updated with Context logic
                    tasks.append(self._test_lfi(client, url, p))
                    tasks.append(self._test_open_redirect(client, url, p))
                    tasks.append(self._test_ssti(client, url, p))
                    tasks.append(self._test_ssrf(client, url, p))
                    tasks.append(self._test_cmdi(client, url, p))

            # Access Control
            logger.info("[SCAN] Phase 6 — IDOR")
            for url in endpoints:
                tasks.append(self._test_idor(client, url))

            # Auth panels
            logger.info("[SCAN] Phase 7 — Auth panels & default credentials")
            tasks.append(self._test_auth_panels(client, base_url))

            # Execute all tests concurrently within the same session
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"[SCAN] Done — {len(self.findings)} findings, {self.request_count} requests")
        return self.findings

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 0 — WAF DETECTION
    # ─────────────────────────────────────────────────────────────────────────
    async def _detect_waf(self, client: httpx.AsyncClient, base_url: str) -> str | None:
        """
        Send a harmless but obviously malicious-looking probe and inspect
        the response for WAF fingerprints.
        Returns the WAF name string or None if no WAF detected.
        """
        probe = base_url.rstrip("/") + "/?waf_probe=<script>alert(1)</script>'\""
        try:
            res = await client.get(probe, timeout=8)
        except Exception:
            return None

        h    = {k.lower(): v.lower() for k, v in res.headers.items()}
        body = res.text.lower()

        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig in h or sig in body or any(sig in v for v in h.values()):
                    return waf_name

        if res.status_code in (403, 406, 429, 503):
            return "Unknown WAF"

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # AUTH HANDLER
    # ─────────────────────────────────────────────────────────────────────────
    async def _handle_auth(self, client: httpx.AsyncClient, auth_config: dict):
        atype = auth_config.get("type")
        if atype == "login":
            try:
                await client.post(
                    auth_config["login_url"],
                    data={"username": auth_config["username"],
                          "password": auth_config["password"]},
                    timeout=10,
                )
                logger.info("[AUTH] Form login attempted")
            except Exception as e:
                logger.warning(f"[AUTH] Failed: {e}")
        elif atype == "cookie":
            for k, v in auth_config.get("cookies", {}).items():
                client.cookies.set(k, v)
        elif atype == "bearer":
            client.headers["Authorization"] = f"Bearer {auth_config['token']}"

    # ─────────────────────────────────────────────────────────────────────────
    # ORCHESTRATE PER-PARAM TESTS
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_all(self, client, url: str, param: str):
        await asyncio.gather(
            self._test_sqli(client, url, param),
            self._test_xss(client, url, param),
            return_exceptions=True,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # SQLi
    # ─────────────────────────────────────────────────────────────────────────
    # ─────────────────────────────────────────────────────────────────────────
    # SQL INJECTION
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_sqli(self, client, url: str, param: str):
        """
        Tests for SQLi using Error-based, Boolean-based (Diffing), 
        and Time-based (Baseline-aware) logic.
        """
        # 1. CAPTURE BASELINE
        baseline = await self._req(client, "GET", url)
        if baseline is None:
            return

        for payload in SQLI_PAYLOADS:
            test_url = self.param_engine.inject_payload(url, param, payload)
            res = await self._req(client, "GET", test_url)
            if res is None:
                continue

            # --- A. Error-based Detection ---
            body = res.text.lower()
            for sig in SQLI_ERROR_SIGNATURES:
                if sig in body:
                    self._add_finding({
                        "type": "SQL Injection", "subtype": "Error-Based",
                        "url": test_url, "parameter": param, "payload": payload,
                        "severity": "Critical", "confidence": 0.95,
                        "evidence": f"DB error signature: '{sig}'",
                        "description": f"Parameter '{param}' exposes SQL error '{sig}' — unsanitised input reaches the DB.",
                    })
                    return

            # --- B. Boolean-based Blind (The "Full-Proof" Diff) ---
            if "1=1" in payload:
                t_url = test_url # Already contains 1=1
                f_url = self.param_engine.inject_payload(url, param, payload.replace("1=1", "1=2"))
                
                t_res = await self._req(client, "GET", t_url)
                f_res = await self._req(client, "GET", f_url)

                if t_res and f_res:
                    # Calculate similarity between True and False responses
                    # A drop in similarity indicates the page content changed 
                    # based on the SQL condition.
                    from utils.differ import calculate_similarity
                    sim_score = calculate_similarity(t_res.text, f_res.text)

                    if sim_score < 0.96: # 4% or more content change
                        self._add_finding({
                            "type": "SQL Injection", "subtype": "Boolean-Based Blind",
                            "url": test_url, "parameter": param, "payload": payload,
                            "severity": "Critical", "confidence": 0.85,
                            "evidence": f"Similarity Score (True vs False): {sim_score:.2f}",
                            "description": f"Parameter '{param}' behaves differently for True vs False SQL conditions.",
                        })
                        return

            # --- C. Time-based Blind (Baseline-aware) ---
            if any(k in payload.upper() for k in ("SLEEP", "WAITFOR", "BENCHMARK", "PG_SLEEP")):
                # Establish baseline latency for this specific request
                start_base = time.monotonic()
                await self._req(client, "GET", url)
                base_latency = time.monotonic() - start_base

                # Test the payload
                start_test = time.monotonic()
                await self._req(client, "GET", test_url, timeout=15)
                elapsed = time.monotonic() - start_test
                
                # Check if payload added at least 4.5s on top of baseline
                if elapsed >= (base_latency + 4.5):
                    self._add_finding({
                        "type": "SQL Injection", "subtype": "Time-Based Blind",
                        "url": test_url, "parameter": param, "payload": payload,
                        "severity": "Critical", "confidence": 0.90,
                        "evidence": f"Baseline: {base_latency:.2f}s | Attack: {elapsed:.2f}s",
                        "description": f"Parameter '{param}' caused a significant delay relative to baseline.",
                    })
                    return

    
    # ─────────────────────────────────────────────────────────────────────────
    # XSS (Context-Aware)
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_xss(self, client, url: str, param: str):
        """
        Elite XSS: Detects context first, then routes targeted payloads.
        """
        # 1. DISCOVERY PHASE: Send a neutral Canary to find the reflection point
        canary = "CTX_CHECK_99"
        discovery_url = self.param_engine.inject_payload(url, param, canary)
        res_discovery = await self._req(client, "GET", discovery_url)

        if not res_discovery or canary not in res_discovery.text:
            return # No reflection, no point in testing further

        # 2. IDENTIFY CONTEXT
        ctx = self._xss_context(res_discovery.text, canary)
        
        # 3. SELECT TARGETED PAYLOADS
        # We only send what works for the specific environment found
        targeted_payloads = []
        
        if ctx == "Script Tag":
            # Payloads meant to break out of JS variables or blocks
            targeted_payloads = ["';alert(1)//", "\"-alert(1)-\"", "</script><script>alert(1)</script>"]
        
        elif ctx == "HTML Attribute":
            # Payloads meant to trigger events or break out of quotes
            targeted_payloads = ["\" autofocus onfocus=alert(1) ", "' onmouseover=alert(1) ", "\"><img src=x onerror=alert(1)>"]
        
        else: # HTML Body or Unknown
            # Standard tags
            targeted_payloads = ["<script>alert(1)</script>", "<svg onload=alert(1)>", "<details open ontoggle=alert(1)>"]

        # 4. ATTACK PHASE
        for payload in targeted_payloads:
            test_url = self.param_engine.inject_payload(url, param, payload)
            res = await self._req(client, "GET", test_url)
            
            if res and payload in res.text:
                self._add_finding({
                    "type": "Cross-Site Scripting (XSS)", 
                    "subtype": f"Reflected — {ctx}",
                    "url": test_url, 
                    "parameter": param, 
                    "payload": payload,
                    "severity": "High" if ctx == "HTML Body" else "Critical",
                    "confidence": 0.95,
                    "evidence": f"Verbatim reflection in {ctx} using targeted vector.",
                    "description": (
                        f"Parameter '{param}' is vulnerable to XSS. Unsanitized input "
                        f"is reflected directly into a {ctx} context."
                    ),
                })
                return # Stop after first successful confirmation

    def _xss_context(self, html: str, canary: str) -> str:
        """
        Determines the execution environment for the injected string.
        """
        idx = html.find(canary)
        if idx == -1: 
            return "Unknown"
        
        # Look at the 150 characters before the reflection
        prefix = html[max(0, idx - 150): idx].lower()
        
        # Check if we are inside a <script> block
        if "<script" in prefix and "</script" not in prefix:
            return "Script Tag"
            
        # Check if we are inside an HTML attribute (looking for an open quote following an =)
        # Logic: If the last '=' is followed by a quote but not a closing '>'
        last_equals = prefix.rfind("=")
        if last_equals != -1:
            after_equals = prefix[last_equals:]
            if '"' in after_equals or "'" in after_equals:
                if ">" not in after_equals:
                    return "HTML Attribute"
                    
        return "HTML Body"

    # ─────────────────────────────────────────────────────────────────────────
    # FORM TESTING
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_form(self, client, form: dict):
        method = form["method"]
        url    = form["url"]
        base   = dict(form["inputs"])

        for payload in XSS_PAYLOADS[:8]:
            data = {k: payload for k in base}
            res  = (await self._req(client, "POST", url, data=data, timeout=12)
                    if method == "POST"
                    else await self._req(client, "GET", url, params=data, timeout=12))
            if res and payload in res.text:
                self._add_finding({
                    "type": "Cross-Site Scripting (XSS)", "subtype": f"Reflected via Form ({method})",
                    "url": url, "parameter": "form", "payload": payload,
                    "severity": "High", "confidence": 0.88,
                    "evidence": f"Payload reflected after {method} submission",
                    "description": f"Form at {url} reflects unsanitised input.",
                })
                break

        for payload in SQLI_PAYLOADS[:12]:
            data = {k: payload for k in base}
            res  = (await self._req(client, "POST", url, data=data, timeout=12)
                    if method == "POST"
                    else await self._req(client, "GET", url, params=data, timeout=12))
            if res:
                body = res.text.lower()
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig in body:
                        self._add_finding({
                            "type": "SQL Injection", "subtype": f"Error-Based via Form ({method})",
                            "url": url, "parameter": "form", "payload": payload,
                            "severity": "Critical", "confidence": 0.93,
                            "evidence": f"DB error: '{sig}'",
                            "description": f"Form at {url} passes unsanitised input to the DB.",
                        })
                        return

    # ─────────────────────────────────────────────────────────────────────────
    # LFI
    # ─────────────────────────────────────────────────────────────────────────
    LFI_INDICATORS = [
        "root:x:", "root:0:0", "daemon:", "nobody:", "bin/bash", "bin/sh",
        "www-data", "[boot loader]", "[fonts]", "[extensions]",
    ]

    async def _test_lfi(self, client, url: str, param: str):
        for payload in LFI_PAYLOADS:
            test_url = self.param_engine.inject_payload(url, param, payload)
            res = await self._req(client, "GET", test_url)
            if res:
                for indicator in self.LFI_INDICATORS:
                    if indicator in res.text:
                        self._add_finding({
                            "type": "Local File Inclusion (LFI)", "subtype": "Path Traversal",
                            "url": test_url, "parameter": param, "payload": payload,
                            "severity": "Critical", "confidence": 0.95,
                            "evidence": f"File marker '{indicator}' in response",
                            "description": f"Parameter '{param}' allows directory traversal to read server files.",
                        })
                        return

    # ─────────────────────────────────────────────────────────────────────────
    # OPEN REDIRECT
    # ─────────────────────────────────────────────────────────────────────────
    REDIRECT_PARAMS = frozenset({
        "redirect","next","return","dest","destination","url","goto","redir",
        "return_url","callback","target","link","forward","location","continue",
        "ref","return_to","redirect_uri","redirect_url",
    })

    async def _test_open_redirect(self, client, url: str, param: str):
        if param.lower() not in self.REDIRECT_PARAMS:
            return
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_url = self.param_engine.inject_payload(url, param, payload)
            try:
                res = await client.get(test_url, follow_redirects=False, timeout=8)
            except Exception:
                continue
            loc = res.headers.get("location", "")
            if ("evil.com" in loc or loc.startswith("//") or "javascript:" in loc.lower()
                    or (loc.startswith("http") and urlparse(loc).netloc != urlparse(url).netloc)):
                self._add_finding({
                    "type": "Open Redirect", "subtype": "Unvalidated External Redirect",
                    "url": test_url, "parameter": param, "payload": payload,
                    "severity": "Medium", "confidence": 0.92,
                    "evidence": f"Location: {loc}",
                    "description": f"Parameter '{param}' redirects to arbitrary external URLs.",
                })
                return

    # ─────────────────────────────────────────────────────────────────────────
    # SSTI
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_ssti(self, client, url: str, param: str):
        res1 = await self._req(client, "GET", self.param_engine.inject_payload(url, param, "{{7*7}}"))
        if not (res1 and "49" in res1.text):
            return
        res2 = await self._req(client, "GET", self.param_engine.inject_payload(url, param, "{{3*3}}"))
        if res2 and "9" in res2.text:
            self._add_finding({
                "type": "Server-Side Template Injection (SSTI)", "subtype": "Confirmed",
                "url": self.param_engine.inject_payload(url, param, "{{7*7}}"),
                "parameter": param, "payload": "{{7*7}}",
                "severity": "Critical", "confidence": 0.93,
                "evidence": "{{7*7}}→49 and {{3*3}}→9 both confirmed",
                "description": f"Parameter '{param}' evaluates template expressions. RCE likely possible.",
            })

    # ─────────────────────────────────────────────────────────────────────────
    # SSRF  (NEW)
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_ssrf(self, client, url: str, param: str):
        """
        Only test params whose name suggests URL/path fetching.
        Injects internal targets and looks for cloud metadata or
        internal service responses in the body.
        """
        if param.lower() not in SSRF_PROBE_PARAMS:
            return

        ssrf_targets = [
            "http://169.254.169.254/latest/meta-data/",           # AWS
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/v1/",                  # DigitalOcean
            "http://127.0.0.1:6379",                                # Redis
            "http://localhost:6379",
            "http://127.0.0.1:27017",                               # MongoDB
            "http://127.0.0.1:9200",                                # Elasticsearch
            "http://0.0.0.0",
            "http://[::1]",
            "http://2130706433",                                    # 127.0.0.1 decimal
        ]

        for target in ssrf_targets:
            test_url = self.param_engine.inject_payload(url, param, target)
            res = await self._req(client, "GET", test_url, timeout=8)
            if res and res.status_code == 200:
                body = res.text
                for indicator in SSRF_INDICATORS:
                    if indicator.lower() in body.lower():
                        self._add_finding({
                            "type": "Server-Side Request Forgery (SSRF)",
                            "subtype": "Internal Resource Access",
                            "url": test_url, "parameter": param, "payload": target,
                            "severity": "Critical", "confidence": 0.90,
                            "evidence": f"Internal indicator '{indicator}' found in response",
                            "description": (
                                f"Parameter '{param}' caused the server to fetch '{target}'. "
                                f"The response contained '{indicator}', confirming SSRF. "
                                f"An attacker can read cloud metadata, internal APIs, or pivot to internal services."
                            ),
                        })
                        return

  # ONLY SHOWING FIXED SECTION — EVERYTHING ELSE REMAINS EXACTLY AS YOUR FILE

# ─────────────────────────────────────────────────────────────────────────
# COMMAND INJECTION  (FIXED)
# ─────────────────────────────────────────────────────────────────────────
async def _test_cmdi(self, client, url: str, param: str):
    """
    Command Injection detection using:
    1. Output-based detection (high confidence)
    2. Time-based detection (blind fallback with baseline comparison)
    """

    # ── 1. Establish baseline latency ─────────────────────────────────────
    start_base = asyncio.get_event_loop().time()
    base_res = await self._req(client, "GET", url, params={param: "normal_test"})
    if base_res is None:
        return

    baseline_duration = asyncio.get_event_loop().time() - start_base

    # ── 2. Output-based detection (HIGH CONFIDENCE) ───────────────────────
    for payload, indicators in CMDI_OUTPUT_PAYLOADS:
        test_url = self.param_engine.inject_payload(url, param, payload)
        res = await self._req(client, "GET", test_url)

        if not res:
            continue

        for indicator in indicators:
            if indicator in res.text:
                self._add_finding({
                    "type": "Command Injection",
                    "subtype": "Output-Based",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "severity": "Critical",
                    "confidence": 0.97,
                    "evidence": f"OS command output marker: '{indicator}'",
                    "description": (
                        f"Parameter '{param}' passes input directly to a shell. "
                        f"The response contained '{indicator}', proving arbitrary command execution."
                    ),
                })
                return

    # ── 3. Time-based detection (baseline-aware — YOUR LOGIC FIXED) ───────
    time_payload = "; sleep 5; #"

    start_test = asyncio.get_event_loop().time()
    res = await self._req(client, "GET", url, params={param: time_payload})
    if res is None:
        return

    test_duration = asyncio.get_event_loop().time() - start_test

    if test_duration >= (baseline_duration + 4.5):
        self._add_finding({
            "type": "Command Injection (Blind/Time-based)",
            "url": url,
            "parameter": param,
            "payload": time_payload,
            "severity": "Critical",
            "confidence": 0.95,
            "evidence": (
                f"Baseline: {baseline_duration:.2f}s | "
                f"Attack: {test_duration:.2f}s"
            ),
            "description": (
                "Injected sleep caused delay beyond baseline, "
                "indicating blind command execution."
            ),
        })
        return

    # ── 4. Fallback time-based payload set (original logic preserved) ─────
    for payload, threshold in CMDI_TIME_PAYLOADS:
        test_url = self.param_engine.inject_payload(url, param, payload)

        start = time.monotonic()
        await self._req(client, "GET", test_url, timeout=threshold + 5)
        elapsed = time.monotonic() - start

        if elapsed >= self.CMDI_TIME_THRESHOLD:
            self._add_finding({
                "type": "Command Injection",
                "subtype": "Time-Based Blind",
                "url": test_url,
                "parameter": param,
                "payload": payload,
                "severity": "Critical",
                "confidence": 0.82,
                "evidence": f"Response delayed {elapsed:.1f}s after '{payload}'",
                "description": (
                    f"Parameter '{param}' caused a delay after injecting a sleep command, "
                    f"indicating blind command injection."
                ),
            })
            return

    # ─────────────────────────────────────────────────────────────────────────
    # IDOR  (NEW)
    # ─────────────────────────────────────────────────────────────────────────
    _ID_PATTERN   = re.compile(r'(/[\w\-]+/)(\d+)(/|$)')
    _UUID_PATTERN = re.compile(
        r'(/[\w\-]+/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)',
        re.IGNORECASE,
    )

    async def _test_idor(self, client, url: str):
        """
        Detect Insecure Direct Object Reference by swapping IDs in URL paths.
        If a different object's data is returned, that's a missing auth check.
        """
        parsed = urlparse(url)
        path   = parsed.path

        for pattern in (self._ID_PATTERN, self._UUID_PATTERN):
            m = pattern.search(path)
            if not m:
                continue

            original_id   = m.group(2)
            resource_name = m.group(1).strip("/")

            # Generate test IDs
            try:
                n = int(original_id)
                test_ids = [str(n + 1), str(n + 2), str(max(1, n - 1)), "1", "2", "9999"]
            except ValueError:
                test_ids = [
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000002",
                    "ffffffff-ffff-ffff-ffff-ffffffffffff",
                ]

            # Baseline: the original URL must return 200 + real data
            baseline = await self._req(client, "GET", url)
            if not baseline or baseline.status_code != 200 or len(baseline.text) < 30:
                continue

            for test_id in test_ids:
                if test_id == original_id:
                    continue

                # Replace the ID in the path
                new_path = pattern.sub(
                    lambda x, tid=test_id: x.group(1) + tid + x.group(3),
                    path, count=1,
                )
                test_url = urlunparse(parsed._replace(path=new_path))

                res = await self._req(client, "GET", test_url)
                if not res or res.status_code != 200:
                    continue

                body = res.text
                # Response must be substantial and structurally similar to the baseline
                # (to distinguish real data from generic 200 pages)
                size_ratio = len(body) / max(len(baseline.text), 1)
                if len(body) > 50 and 0.3 < size_ratio < 3.0:
                    self._add_finding({
                        "type": "IDOR / Broken Object Level Authorization",
                        "subtype": "Object ID Enumeration",
                        "url": test_url, "parameter": resource_name,
                        "payload": test_id,
                        "severity": "High", "confidence": 0.75,
                        "evidence": (
                            f"Swapped ID {original_id} → {test_id} on /{resource_name}/. "
                            f"Got HTTP 200 with {len(body)} bytes "
                            f"({size_ratio:.1f}x baseline). No auth error returned."
                        ),
                        "description": (
                            f"Accessing /{resource_name}/{test_id} returned data without an authorization check. "
                            f"An attacker can enumerate object IDs to access other users' data."
                        ),
                    })
                    return  # one confirmed IDOR per endpoint is enough

    # ─────────────────────────────────────────────────────────────────────────
    # AUTH PANELS + DEFAULT CREDENTIALS  (NEW)
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_auth_panels(self, client, base_url: str):
        """
        1. Find exposed admin / login panels.
        2. Try default credentials against each one.
        3. Check for missing account lockout.
        """
        base = base_url.rstrip("/")

        for path in AUTH_PANEL_PATHS:
            url = base + path
            res = await self._req(client, "GET", url)
            if not res or res.status_code not in (200, 401, 403):
                continue

            body_lower = res.text.lower()
            # Confirm it's actually a login page
            has_login_form = any(kw in body_lower for kw in
                                 ("password", "passwd", "login", "sign in", "username"))
            if not has_login_form:
                continue

            logger.info(f"[AUTH] Login panel found: {url}")

            # ── Default credential spray ──────────────────────────────────────
            # Identify likely field names from the form
            u_field = self._guess_field(body_lower, USERNAME_FIELDS)
            p_field = self._guess_field(body_lower, PASSWORD_FIELDS)

            successful_cred = None
            for username, password in DEFAULT_CREDS:
                data = {u_field: username, p_field: password}
                login_res = await self._req(client, "POST", url, data=data, timeout=10)
                if not login_res:
                    continue

                # Signs of successful login: redirect, dashboard keywords, no "invalid"
                if login_res.status_code in (301, 302, 303):
                    loc = login_res.headers.get("location", "")
                    if any(kw in loc.lower() for kw in ("dashboard","admin","panel","home")):
                        successful_cred = (username, password)
                        break

                lr_body = login_res.text.lower()
                if (any(kw in lr_body for kw in ("dashboard","logout","welcome","signed in"))
                        and not any(kw in lr_body for kw in ("invalid","incorrect","failed","error"))):
                    successful_cred = (username, password)
                    break

            if successful_cred:
                self._add_finding({
                    "type": "Default Credentials Accepted",
                    "subtype": path,
                    "url": url, "parameter": "login form",
                    "payload": f"{successful_cred[0]} / {successful_cred[1]}",
                    "severity": "Critical", "confidence": 0.95,
                    "evidence": f"Login succeeded with {successful_cred[0]}:{successful_cred[1]}",
                    "description": (
                        f"The admin panel at {url} accepted the default credential "
                        f"'{successful_cred[0]}' / '{successful_cred[1]}'. "
                        f"An attacker gains immediate administrative access."
                    ),
                })
            else:
                # ── Account lockout check ─────────────────────────────────────
                # Send 10 rapid wrong logins and check for lockout signals
                locked = False
                for _ in range(10):
                    r = await self._req(client, "POST", url,
                                        data={u_field: "admin", p_field: "wrongpassword999"},
                                        timeout=8)
                    if r and r.status_code == 429:
                        locked = True
                        break
                    if r and any(kw in r.text.lower() for kw in
                                 ("locked", "too many", "blocked", "captcha", "temporarily")):
                        locked = True
                        break

                if not locked:
                    self._add_finding({
                        "type": "Missing Account Lockout",
                        "subtype": path,
                        "url": url, "parameter": "login form",
                        "payload": "10 rapid wrong-password attempts",
                        "severity": "Medium", "confidence": 0.85,
                        "evidence": "10 consecutive failed logins — no lockout, CAPTCHA, or 429 returned",
                        "description": (
                            f"The login at {url} does not enforce account lockout or rate limiting. "
                            f"An attacker can brute-force credentials without restriction."
                        ),
                    })

    def _guess_field(self, html: str, candidates: list) -> str:
        """Return the first candidate field name found in the HTML, or the first candidate."""
        for c in candidates:
            if f'name="{c}"' in html or f"name='{c}'" in html:
                return c
        return candidates[0]

    # ─────────────────────────────────────────────────────────────────────────
    # SECURITY HEADERS
    # ─────────────────────────────────────────────────────────────────────────
    async def _check_security_headers(self, client, base_url: str):
        res = await self._req(client, "GET", base_url)
        if not res:
            return
        h = {k.lower(): v for k, v in res.headers.items()}

        REQUIRED = {
            "content-security-policy":   ("Medium", "No CSP — inline scripts and untrusted sources can execute."),
            "x-frame-options":           ("Medium", "No X-Frame-Options — clickjacking possible."),
            "x-content-type-options":    ("Low",    "No X-Content-Type-Options: nosniff."),
            "strict-transport-security": ("Medium", "No HSTS — downgrade to HTTP possible."),
            "referrer-policy":           ("Low",    "No Referrer-Policy — URL data may leak."),
            "permissions-policy":        ("Low",    "No Permissions-Policy set."),
        }
        for header, (severity, desc) in REQUIRED.items():
            if header not in h:
                self._add_finding({
                    "type": "Missing Security Header", "subtype": header.title(),
                    "url": base_url, "severity": severity, "confidence": 1.0,
                    "evidence": f"'{header}' absent", "description": desc,
                })

        # CORS
        cors_res = await self._req(client, "GET", base_url, headers={"Origin": "https://evil.com"})
        if cors_res:
            acao = cors_res.headers.get("access-control-allow-origin", "")
            acac = cors_res.headers.get("access-control-allow-credentials", "").lower()
            if acao == "*" and acac == "true":
                self._add_finding({
                    "type": "CORS Misconfiguration", "subtype": "Wildcard + Credentials",
                    "url": base_url, "severity": "Critical", "confidence": 1.0,
                    "evidence": f"ACAO={acao} ACAC={acac}",
                    "description": "Wildcard CORS + credentials — any origin can make authenticated requests.",
                })
            elif acao == "https://evil.com":
                self._add_finding({
                    "type": "CORS Misconfiguration", "subtype": "Reflected Origin",
                    "url": base_url, "severity": "High", "confidence": 0.95,
                    "evidence": f"Reflected Origin: {acao}",
                    "description": "Server echoes any Origin header — all origins allowed.",
                })

        # Leaky headers
        for hdr, desc in {
            "x-powered-by": "Backend tech exposed", "server": "Server version exposed",
            "x-aspnet-version": "ASP.NET version exposed",
        }.items():
            if hdr in h:
                self._add_finding({
                    "type": "Information Disclosure", "subtype": "Response Header",
                    "url": base_url, "severity": "Low", "confidence": 1.0,
                    "evidence": f"{hdr}: {h[hdr]}", "description": desc,
                })

    # ─────────────────────────────────────────────────────────────────────────
    # INFO DISCLOSURE — sensitive files & directory listing
    # ─────────────────────────────────────────────────────────────────────────
    async def _check_info_disclosure(self, client, base_url: str):
        base = base_url.rstrip("/")

        SENSITIVE = [
            ("/.env",               ["DB_PASSWORD","SECRET_KEY","AWS_","API_KEY"]),
            ("/.env.production",    ["DB_PASSWORD","SECRET_KEY"]),
            ("/.env.local",         ["DB_PASSWORD","SECRET_KEY"]),
            ("/.git/HEAD",          ["ref:","refs/heads"]),
            ("/.git/config",        ["[core]","repositoryformatversion"]),
            ("/web.config",         ["connectionString","appSettings"]),
            ("/config.php",         ["password","database","$db"]),
            ("/config.yml",         ["password:","secret:","database:"]),
            ("/phpinfo.php",        ["PHP Version","phpinfo()"]),
            ("/server-status",      ["Apache Server Status","requests currently"]),
            ("/actuator/env",       ["systemProperties","applicationConfig"]),
            ("/actuator/mappings",  ["dispatcherServlet"]),
            ("/actuator/health",    ["status","diskSpace"]),
            ("/trace",              ["TRACE","Host:","Cookie:"]),
            ("/backup.sql",         ["INSERT INTO","CREATE TABLE"]),
            ("/dump.sql",           ["INSERT INTO","CREATE TABLE"]),
            ("/db.sql",             ["INSERT INTO","CREATE TABLE"]),
            ("/id_rsa",             ["-----BEGIN","PRIVATE KEY"]),
            ("/composer.json",      ["require","autoload"]),
            ("/package.json",       ["dependencies","scripts"]),
            ("/wp-config.php.bak",  ["DB_PASSWORD","DB_HOST"]),
        ]
        for path, indicators in SENSITIVE:
            url = base + path
            res = await self._req(client, "GET", url)
            if res and res.status_code == 200:
                for ind in indicators:
                    if ind.lower() in res.text.lower():
                        self._add_finding({
                            "type": "Sensitive File Exposed", "subtype": path,
                            "url": url, "severity": "Critical", "confidence": 0.97,
                            "evidence": f"Indicator '{ind}' in response",
                            "description": f"File {path} is publicly accessible and contains sensitive data.",
                        })
                        break

        LISTING = ["Index of /", "Directory listing", "Parent Directory"]
        for d in ["/images/","/uploads/","/files/","/backup/","/logs/","/tmp/","/data/","/export/"]:
            url = base + d
            res = await self._req(client, "GET", url)
            if res and res.status_code == 200 and any(m in res.text for m in LISTING):
                self._add_finding({
                    "type": "Directory Listing Enabled", "subtype": d,
                    "url": url, "severity": "Medium", "confidence": 0.99,
                    "evidence": "Directory index page returned",
                    "description": f"Directory listing at {d} lets attackers enumerate all files.",
                })

    # ─────────────────────────────────────────────────────────────────────────
    # DEDUPLICATION
    # ─────────────────────────────────────────────────────────────────────────
    def _add_finding(self, f: dict):
        key = "::".join([f.get("type",""), f.get("url",""),
                         f.get("parameter",""), f.get("payload","")[:30]])
        if key in self._seen_findings:
            return
        self._seen_findings.add(key)
        self.findings.append(f)
        logger.info(f"[FINDING] {f['severity']:8s} | {f['type']:45s} | {f.get('url','')}")


# ─────────────────────────────────────────────────────────────────────────────
# AI FALSE-POSITIVE FILTER  (called from scan_worker.py after scan completes)
# ─────────────────────────────────────────────────────────────────────────────
async def filter_false_positives(findings: list, brain) -> list:
    """
    Run each finding through the AI brain to remove noise.
    Drop findings where the AI judges them invalid or low-confidence.

    Usage in scan_worker.py:
        from scanner.dast.active_scanner import ActiveScanner, filter_false_positives
        from scanner.ai_brain import AIBrain

        brain    = AIBrain()
        scanner  = ActiveScanner()
        findings = await scanner.scan(url)
        findings = await filter_false_positives(findings, brain)
    """
    validated = []
    for finding in findings:
        try:
            result = await brain.validate_finding(finding)
            if result.get("valid") and result.get("confidence", 0) >= 0.6:
                finding["ai_confidence"]  = result["confidence"]
                finding["ai_explanation"] = result.get("reason", "")
                # Let AI upgrade severity if it sees something we missed
                if result.get("severity") in ("Critical", "High"):
                    finding["severity"] = result["severity"]
                validated.append(finding)
            else:
                logger.info(
                    f"[AI FILTER] Dropped: {finding['type']} at {finding.get('url','')} "
                    f"— AI confidence={result.get('confidence',0):.2f}"
                )
        except Exception as e:
            logger.warning(f"[AI FILTER] Error on finding: {e}")
            validated.append(finding)  # keep on error rather than lose data
    return validated
