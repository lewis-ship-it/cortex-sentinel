# scanner/dast/active_scanner.py
#
# FIXES:
#   1. self.target_url — added attribute, set in scan()
#   2. _detect_waf_and_tech — method was called but never defined; now implemented
#   3. crawler.crawl() return format — crawler returns (list[str], list[dict])
#      scan() was treating it as a list of {url, params, forms} dicts — WRONG.
#      Fixed to properly unpack (endpoints, forms) then pass to modules.
#   4. finalize_and_report — was indented inside filter_false_positives (dead code).
#      Moved to be a proper class method.
#   5. filter_false_positives — called brain.analyze_attack_surface which doesn't
#      exist on AIBrain; changed to brain.validate_finding.
#   6. log_event(self.job_id) — guarded so None job_id doesn't crash.

import asyncio
import json
import logging
import random
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from scanner.dast.crawler import Crawler
from scanner.dast.param_engine import ParamEngine
from scanner.dast.context_engine import ContextEngine
from scanner.dast.waf_detector import WAFDetector
from scanner.dast.graphql_engine import check_graphql_introspection
from task_queue.redis_client import log_event

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
    ("/.env",              ["DB_PASSWORD","SECRET_KEY","AWS_","API_KEY"]),
    ("/.env.local",        ["DB_PASSWORD","SECRET_KEY"]),
    ("/.env.production",   ["DB_PASSWORD","SECRET_KEY"]),
    ("/.git/HEAD",         ["ref:","refs/heads"]),
    ("/.git/config",       ["[core]","repositoryformatversion"]),
    ("/web.config",        ["connectionString","appSettings"]),
    ("/config.php",        ["password","database","$db"]),
    ("/phpinfo.php",       ["PHP Version","phpinfo()"]),
    ("/server-status",     ["Apache Server Status"]),
    ("/actuator/env",      ["systemProperties","applicationConfig"]),
    ("/actuator/mappings", ["dispatcherServlet"]),
    ("/backup.sql",        ["INSERT INTO","CREATE TABLE"]),
    ("/dump.sql",          ["INSERT INTO","CREATE TABLE"]),
    ("/id_rsa",            ["-----BEGIN","PRIVATE KEY"]),
    ("/composer.json",     ["require","autoload"]),
    ("/package.json",      ["dependencies","scripts"]),
]

LISTING_MARKERS = ["Index of /","Directory listing","Parent Directory"]


class ActiveScanner:
    MAX_REQUESTS = 5000
    CONCURRENCY  = 12

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
        self.target_url     = ""   # FIX: was missing — caused AttributeError in _req

    # ─────────────────────────────────────────────────────────────────────────
    # THROTTLE
    # ─────────────────────────────────────────────────────────────────────────
    async def _human_delay(self, url: str) -> None:
        if self.request_count > 0 and self.request_count % BURST_EVERY == 0:
            await asyncio.sleep(random.uniform(*BURST_PAUSE))
            return
        host    = urlparse(url).netloc
        now     = asyncio.get_event_loop().time()
        elapsed = now - self._last_req_ts.get(host, 0.0)
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
            # FIX: self.target_url now always exists
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
    # FIX: _detect_waf_and_tech — was called in scan() but never defined
    # ─────────────────────────────────────────────────────────────────────────
    async def _detect_waf_and_tech(self, client, base_url: str) -> None:
        """Detects WAF presence and fingerprints technology stack."""
        # WAF detection
        self.waf_name = await self.waf_detector.detect(client, base_url)
        if self.waf_name and self.waf_name != "Generic":
            logger.warning(f"[WAF] Detected: {self.waf_name}")
            log_event(self.job_id, "WAF", f"WAF detected: {self.waf_name}")

        # Tech fingerprint from homepage
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
        if "php" in x_powered or ".php" in str(res.url):   tech.append("PHP")
        if "express" in x_powered or "node" in server:      tech.append("Node.js")
        if "csrftoken" in cookies or "django" in body:      tech.append("Django")
        if "flask" in cookies:                               tech.append("Flask")
        if "asp.net" in x_powered or "iis" in server:       tech.append("ASP.NET")
        if "wp-content" in body or "wp-json" in body:       tech.append("WordPress")
        if "laravel" in cookies or "laravel" in body:        tech.append("Laravel")
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
        self.target_url     = base_url   # FIX: set here so _req can use it

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

        audit_semaphore = asyncio.Semaphore(5)

        async with httpx.AsyncClient(timeout=20, verify=False, follow_redirects=True) as client:
            if auth_config:
                await self._handle_auth(client, auth_config)

            # Phase 0+1: WAF + Tech fingerprint (FIX: method now defined)
            await self._detect_waf_and_tech(client, base_url)

            # Phase 2: Crawl
            # FIX: crawler.crawl() returns (list[str], list[dict]) — unpack correctly
            crawler = Crawler(base_url)
            endpoints, forms = await crawler.crawl(client)
            log_event(self.job_id, "CRAWL", f"Found {len(endpoints)} endpoints, {len(forms)} forms")

            # Phase 3: Recon
            await asyncio.gather(
                self._check_security_headers(client, base_url),
                self._check_sensitive_files(client, base_url),
                self._run_graphql_check(client, base_url),
                return_exceptions=True,
            )

            # Phase 4: Module execution
            # FIX: pass url (str) directly — not item["url"] from a dict
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

            # Phase 5: OAST polling
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
            for variant in self.param_engine.add_param_variants(url)[:5]:
                params = self.param_engine.extract_params(variant)
                if params:
                    url = variant
                    break
        if not params:
            return

        from scanner.dast.modules.injection import InjectionModule
        from scanner.dast.modules.client_side import ClientSideModule
        from scanner.dast.modules.infra import InfraModule
        from scanner.dast.modules.access import AccessModule

        mods = [InjectionModule(self), ClientSideModule(self), InfraModule(self), AccessModule(self)]
        await asyncio.gather(*(m.run(client, url, params) for m in mods), return_exceptions=True)

    async def _run_form_modules(self, client, form: dict) -> None:
        from scanner.dast.modules.injection import InjectionModule
        from scanner.dast.modules.client_side import ClientSideModule
        await asyncio.gather(
            InjectionModule(self).test_form(client, form),
            ClientSideModule(self).test_form_xss(client, form),
            return_exceptions=True,
        )

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
        }
        for header, (sev, desc) in REQUIRED.items():
            if header not in h:
                self._add_finding({
                    "type":"Missing Security Header","subtype":header.title(),
                    "url":base_url,"severity":sev,"confidence":1.0,
                    "evidence":f"'{header}' absent","description":desc,
                })
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
            for ind in indicators:
                if ind.lower() in res.text.lower():
                    self._add_finding({
                        "type":"Sensitive File Exposed","subtype":path,
                        "url":url,"severity":"Critical","confidence":0.97,
                        "evidence":f"Indicator '{ind}' found",
                        "description":f"File {path} is publicly accessible.",
                    })
                    break
        for d in ["/uploads/","/backup/","/logs/","/files/","/tmp/"]:
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
    # FIX: finalize_and_report now a proper class method (was trapped in wrong scope)
    # ─────────────────────────────────────────────────────────────────────────
    async def finalize_and_report(self) -> dict:
        """Save usage metrics and return final cost summary."""
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
# AI FALSE-POSITIVE FILTER (module-level, imported by workers)
# FIX: was calling brain.analyze_attack_surface — method doesn't exist on AIBrain.
#      Changed to brain.validate_finding which is the actual method.
# ─────────────────────────────────────────────────────────────────────────────
async def filter_false_positives(findings: list, brain) -> list:
    validated = []
    for f in findings:
        # OAST hits bypass filtering — they're definitively confirmed
        if "OAST" in f.get("type","") or f.get("confidence",0) > 0.98:
            f["ai_confidence"]  = 1.0
            f["ai_explanation"] = "Verified via out-of-band interaction."
            validated.append(f)
            continue
        try:
            # FIX: validate_finding is the correct method name
            result = await brain.validate_finding(f)
            conf = result.get("confidence", 0)
            if result.get("valid") and conf >= 0.65:
                f["ai_confidence"]  = conf
                f["ai_explanation"] = result.get("reason","")
                validated.append(f)
            else:
                logger.info(f"[AI FILTER] Dropped: {f.get('type')} (conf={conf:.2f})")
        except Exception as e:
            logger.warning(f"[AI FILTER] Error: {e}")
            f["ai_confidence"] = 0.5
            validated.append(f)
    return validated
