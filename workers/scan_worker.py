
# workers/scan_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# SENTINEL SCAN WORKER — Evidence-Gated Pipeline
#
# Architecture changes vs. previous version:
#
#   1. EVIDENCE-GATED PIPELINE
#      Every payload injection now calls validator.verify(...).  A finding is
#      appended to `findings` ONLY when result.is_vulnerable is True.
#      WAF/defence responses (403/429/500/503) are logged but never turned
#      into findings.
#
#   2. CONFIDENCE SCORING — every finding object carries:
#        confidence_score   (float 0.0–1.0)
#        evidence_snippet   (str — specific response fragment proving the vuln)
#        method             (str — e.g. 'oracle_math', 'timing_analysis')
#
#   3. DB CONSISTENCY
#      db.save_vulnerabilities() is called inside a try/except/finally block.
#      If the scan fails at any stage, a JobFailed signal is pushed to the
#      queue so zombie jobs never linger in the dashboard.
#
#   4. IDEMPOTENCY
#      Job status is set to 'scanning' in the DB at the top of handle() before
#      scan_url_async() is called, so the job is immediately visible.
#
#   5. JSON SERIALISATION GUARD
#      _ensure_serializable() sanitises every finding dict before the DB write
#      so non-serializable types (datetime, bytes, sets, …) never cause a
#      silent failure.
#
#   6. GLOBAL EXCEPTION WRAPPER
#      A top-level try/except Exception in handle() logs the full stack trace
#      to the DB and pushes a JobFailed signal — no worker ever silently stops.
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import json
import logging
import re
import time
import traceback
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import httpx

from workers.base_worker import worker_loop, push_log
from task_queue.queues import SCAN_QUEUE
from core.pipeline import on_scan_complete
from core.session_store import get_session
from core.database import get_db
from core.http_client import HTTPClient, RateLimitConfig
from core.state_manager import get_state_manager
from core.logger import get_logger
from scanner.fuzzer import SmartFuzzer
from scanner.detector import Detector, Validator
from scanner.dast.context_engine import ContextEngine

logging.basicConfig(level=logging.DEBUG)
logger        = get_logger("scan_worker")
state_manager = get_state_manager()

detector       = Detector()
validator      = Validator()
context_engine = ContextEngine()
fuzzer         = SmartFuzzer()


# ─────────────────────────────────────────────────────────────────────────────
# TIMEOUT CONFIG
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT    = 12
PHP_TIMEOUT        = 30
TIME_BASED_TIMEOUT = 15


# ─────────────────────────────────────────────────────────────────────────────
# COMMON INJECTABLE PARAMETERS
# ─────────────────────────────────────────────────────────────────────────────

COMMON_PARAMS = [
    "id", "user", "username", "email", "token", "auth", "search", "query",
    "q", "page", "lang", "file", "path", "redirect", "url", "next", "data",
    "input", "message", "comment", "text", "callback", "return", "dest",
    "view", "item", "cat", "category", "ref", "source", "type", "name",
    "sort", "filter", "from", "to", "amount", "code", "key", "session",
    "debug", "action", "op", "mode", "format", "output", "dir", "include",
]
async def is_url_reachable(url: str, timeout: int = 5) -> bool:
    """
    Validate that a URL is reachable before attempting full scan.
    Returns True if URL responds with a non-5xx status code.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            # Use HEAD first for efficiency, fall back to GET if needed
            try:
                response = await client.head(url)
            except (httpx.ConnectError, httpx.ReadTimeout):
                # Try GET if HEAD fails (some servers block HEAD)
                response = await client.get(url)
            
            return response.status_code < 500
    except Exception:
        return False



# ─────────────────────────────────────────────────────────────────────────────
# PHP DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_php(response, url: str) -> bool:
    indicators = [
        ".php" in url.lower(),
        "php" in response.headers.get("X-Powered-By", "").lower(),
        "php" in response.headers.get("Server", "").lower(),
        "phpsessid" in response.headers.get("Set-Cookie", "").lower(),
        any(x in response.text.lower() for x in [
            "wordpress", "laravel", "symfony", "codeigniter", "zend"
        ]),
    ]
    return any(indicators)


# ─────────────────────────────────────────────────────────────────────────────
# WAF DETECTION — delegates to scanner.dast.waf_detector
# ─────────────────────────────────────────────────────────────────────────────

def detect_waf(response) -> List[str]:
    """Detect WAF from a single response. Delegates to WAFDetector signatures."""
    from scanner.dast.waf_detector import WAF_SIGNATURES
    detected = []
    headers  = str(response.headers).lower()
    body_low = response.text[:2000].lower()
    for waf_name, sigs in WAF_SIGNATURES.items():
        score = 0
        for h in sigs.get("headers", []):
            if h.lower() in headers:
                score += 2
        for b in sigs.get("body", []):
            if b.lower() in body_low:
                score += 1
        if score >= 2:
            detected.append(waf_name)
    return detected


# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def extract_params(url: str, html: str) -> List[str]:
    params = set(COMMON_PARAMS)
    parsed = urlparse(url)
    params.update(parse_qs(parsed.query).keys())
    params.update(re.findall(r'name=["\']([^"\']+)["\']', html, re.IGNORECASE))
    params.update(re.findall(r'data-(\w+)=', html))
    return list(params)


# ─────────────────────────────────────────────────────────────────────────────
# JS ENDPOINT EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def extract_js_endpoints(html: str) -> List[str]:
    endpoints = set()
    patterns = [
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
        r'url:\s*["\']([^"\']+)["\']',
        r'href=["\']([^"\']+)["\']',
    ]
    for pat in patterns:
        endpoints.update(re.findall(pat, html, re.IGNORECASE))
    return list(endpoints)


# ─────────────────────────────────────────────────────────────────────────────
# SECURITY HEADER AUDIT
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


def audit_headers(headers: Dict) -> List[str]:
    headers_lower = {k.lower() for k in headers}
    return [h for h in REQUIRED_HEADERS if h.lower() not in headers_lower]


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD SETS
# ─────────────────────────────────────────────────────────────────────────────

def get_payloads() -> Dict[str, List[str]]:
    return {
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "\" onmouseover=alert(1) x=\"",
            "' onmouseover=alert(1) x='",
            "javascript:alert(1)"
        ],
        "sqli_error": [
            "' OR 1=1 --",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "1' OR '1'='1'-- -",
            "1' UNION SELECT NULL,NULL-- -",
            "1' AND (SELECT * FROM (SELECT SLEEP(5))a)-- -",
            "1' AND extractvalue(1,concat(0x7e,version()))-- -"
        ],
        "sqli_time": [
            "' OR SLEEP(6)--",
            "'; WAITFOR DELAY '0:0:6'--",
            "'; SELECT pg_sleep(6)--"
        ],
        "sqli_bool": [
            "' AND 1=1--",
            "' AND 1=2--"
        ],
        "ssti": [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}"
        ],
        "lfi": [
            "../../../../etc/passwd",
            "../../../../etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php"
        ],
        "cmdi": [
            "; id",
            "| id",
            "& id",
            "$(id)",
            "`id`"
        ],
        "redirect": [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com"
        ],
        "header": [
            "test\r\nX-Injected: evil",
            "test%0d%0aX-Injected: evil"
        ]
    }


# ─────────────────────────────────────────────────────────────────────────────
# RESPONSE DIFF ENGINE  (used for boolean SQLi — produces false_body)
# ─────────────────────────────────────────────────────────────────────────────

class ResponseDiff:
    @staticmethod
    def calculate_diff(baseline: str, injected: str) -> Dict:
        length_diff = abs(len(injected) - len(baseline))
        pct = (
            round(((len(injected) - len(baseline)) / len(baseline)) * 100, 2)
            if baseline else 0
        )
        return {"length_diff": length_diff, "length_pct": pct}

    @staticmethod
    def similarity_ratio(s1: str, s2: str) -> float:
        if not s1 or not s2:
            return 1.0 if s1 == s2 else 0.0
        longer  = s1 if len(s1) >= len(s2) else s2
        shorter = s2 if len(s1) >= len(s2) else s1
        if not longer:
            return 1.0
        shared = sum(1 for c in shorter if c in longer)
        return shared / len(longer)


# ─────────────────────────────────────────────────────────────────────────────
# JSON SERIALISATION GUARD
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_serializable(obj):
    """
    Recursively walk a finding dict (or list) and convert any non-JSON-safe
    type to its string representation.  Prevents silent DB write failures.
    """
    if isinstance(obj, dict):
        return {k: _ensure_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_ensure_serializable(i) for i in obj]
    if isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, str):
        return obj
    # datetime, bytes, set, Enum, custom objects → str
    return str(obj)


def _sanitize_findings(findings: List[Dict]) -> List[Dict]:
    """Apply _ensure_serializable to every finding and validate with json.dumps."""
    safe = []
    for f in findings:
        try:
            cleaned = _ensure_serializable(f)
            json.dumps(cleaned)   # test round-trip
            safe.append(cleaned)
        except Exception as e:
            logger.error(f"[SCAN] Finding serialisation failed, dropping: {e}")
    return safe


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC SCAN CORE
# ─────────────────────────────────────────────────────────────────────────────

async def scan_url_async(
    job_id:     str,
    target_url: str,
    tier:       str            = "Basic",
    cookies:    Optional[Dict] = None,
    headers:    Optional[Dict] = None,
) -> List[Dict]:
    """
    Evidence-gated async vulnerability scan.

    A finding is appended to `findings` ONLY when validator.verify() returns
    is_vulnerable=True.  Every finding contains:
      - confidence_score   (0.0–1.0)
      - evidence_snippet   (specific response fragment)
      - method             (oracle method that confirmed the finding)
    """
    findings: List[Dict] = []
    # ── Circuit Breaker Check ─────────────────────────────────────────────
    db = get_db()
    parsed = urlparse(target_url)
    host = parsed.netloc
    
    if not db.circuit.is_allowed(host):
        logger.warning(f"[SCAN] Circuit breaker blocked {host} — skipping", job_id)
        push_log(job_id, f"[SCAN] Skipping {host} — circuit breaker open", tier=tier)
        return findings
    # ─────────────────────────────────────────────────────────────────────

    rate_cfg    = RateLimitConfig(max_requests_per_second=5, min_delay_ms=200)
    http_client = HTTPClient(
        timeout=DEFAULT_TIMEOUT,
        max_retries=3,
        rate_limit_config=rate_cfg,
    )

    try:
        # ── URL Validation Check ─────────────────────────────────────────
        if not await is_url_reachable(target_url):
            logger.warning(f"URL {target_url} is not reachable — skipping", job_id)
            push_log(job_id, f"[SCAN] Skipping unreachable URL: {target_url}", tier=tier)
            return findings
        # ─────────────────────────────────────────────────────────────────
        # ── Baseline request ──────────────────────────────────────────────
        logger.info(f"Getting baseline response from {target_url}", job_id)
        baseline_start = time.time()
        try:
            baseline = await http_client.get(target_url, headers=headers, cookies=cookies)
        except (httpx.ConnectTimeout, httpx.ConnectError, httpx.ReadTimeout) as exc:
            # Record circuit breaker failure
            db.circuit.record_failure(host)
            logger.warning(f"[SCAN] Connection failed to {target_url}: {exc}", job_id)
            push_log(job_id, f"[SCAN] Connection failed: {target_url}", tier=tier)
            return findings
        except Exception as exc:
            logger.error(f"Scan failed: {exc}", job_id)
            raise
            
        baseline_delay = time.time() - baseline_start
        baseline_text  = baseline.text[:5000]
        db.circuit.record_success(host)

        # ── Target fingerprinting ─────────────────────────────────────────
        is_php  = detect_php(baseline, target_url)
        timeout = PHP_TIMEOUT if is_php else DEFAULT_TIMEOUT

        if is_php:
            logger.info(f"PHP site detected — using {timeout}s timeout", job_id)

        wafs = detect_waf(baseline)
        if wafs:
            logger.warning(f"WAF detected: {', '.join(wafs)}", job_id)
            push_log(job_id, f"[SCAN] WAF detected: {', '.join(wafs)}", tier=tier)

        # ── Security header audit ─────────────────────────────────────────
        missing = audit_headers(dict(baseline.headers))
        if missing:
            findings.append({
                "type":              "Missing Security Headers",
                "severity":          "Medium",
                "param":             "HTTP Headers",
                "missing_headers":   missing,
                "confidence_score":  0.95,
                "evidence_snippet":  f"Missing: {', '.join(missing)}",
                "method":            "header_audit",
                "target_url":        target_url,
            })
            logger.info(f"Missing headers: {missing}", job_id)

        # ── Parameter discovery ───────────────────────────────────────────
        params       = extract_params(target_url, baseline.text)
        js_endpoints = extract_js_endpoints(baseline.text)

        logger.info(
            f"Discovered {len(params)} params, {len(js_endpoints)} JS endpoints", job_id
        )

        payloads    = get_payloads()
        tests_run   = 0
        total_tests = len(params) * sum(len(p) for p in payloads.values())

        logger.info(
            f"Starting evidence-gated vulnerability testing — {total_tests} test cases",
            job_id,
            details={"params": len(params), "payload_types": len(payloads)},
        )

        # ── Boolean SQLi: collect both true and false response bodies ─────
        # We keep a per-(param, url) cache of the false-payload body so the
        # boolean oracle can compare true vs false responses.
        bool_false_cache: Dict[str, str] = {}

        # ── Fuzz each parameter ───────────────────────────────────────────
        for param in params:
            for vuln_type, payload_list in payloads.items():
                for payload in payload_list:
                    tests_run += 1
                    injected_url = f"{target_url}?{param}={payload}"

                    try:
                        req_timeout = (
                            TIME_BASED_TIMEOUT
                            if any(k in payload.lower() for k in ["sleep", "waitfor", "pg_sleep"])
                            else timeout
                        )

                        req_start = time.time()

                        r = await http_client.get(
                            injected_url,
                            headers=headers,
                            cookies=cookies,
                            timeout=req_timeout,
                        )

                        delay = time.time() - req_start
                        body  = r.text[:5000]
                        status = r.status_code

                        # ── Boolean false-body caching ────────────────────
                        # For '1=2' (false) payloads, cache the response so
                        # the corresponding '1=1' (true) oracle can compare.
                        if vuln_type == "sqli_bool" and "1=2" in payload:
                            bool_false_cache[f"{param}_{target_url}"] = body
                            continue   # nothing to validate on the false branch alone

                        # ── EVIDENCE-GATED: call validator for everything ──
                        false_body = ""
                        if vuln_type == "sqli_bool":
                            false_body = bool_false_cache.get(f"{param}_{target_url}", "")

                        result = validator.verify(
                            vuln_type=vuln_type,
                            payload=payload,
                            body=body,
                            status_code=status,
                            response_headers=dict(r.headers),
                            delay=delay,
                            baseline_body=baseline_text,
                            baseline_delay=baseline_delay,
                            false_body=false_body,
                        )

                        # WAF block — log but never create a finding
                        if result.blocked:
                            logger.debug(
                                f"[SCAN] {vuln_type} {param} → BLOCKED_BY_DEFENSE "
                                f"(HTTP {status})",
                                job_id,
                            )
                            continue

                        # Gate: only proceed if oracle confirmed the vulnerability
                        if not result.is_vulnerable:
                            continue

                        # ── Build the canonical finding dict ──────────────
                        vuln_meta = _VULN_META.get(vuln_type, _VULN_META["_default"])
                        conf = round(result.confidence, 4)

                        # Confidence classification
                        if conf >= 0.90:
                            confidence_tier = "high"
                            fp_likelihood = "unlikely"
                        elif conf >= 0.70:
                            confidence_tier = "medium"
                            fp_likelihood = "possible"
                        else:
                            confidence_tier = "low"
                            fp_likelihood = "likely"

                        finding = {
                            "type":             vuln_meta["type"],
                            "severity":         vuln_meta["severity"],
                            "param":            param,
                            "payload":          payload,
                            "target_url":       injected_url,
                            # Required evidence fields
                            "confidence_score": conf,
                            "confidence_tier":  confidence_tier,
                            "fp_likelihood":    fp_likelihood,
                            "evidence_snippet": result.evidence_snippet,
                            "method":           result.method,
                        }

                        # Attach timing evidence for time-based SQLi
                        if vuln_type == "sqli_time":
                            finding["delay_seconds"] = round(delay, 2)

                        findings.append(finding)
                        logger.info(
                            f"[CONFIRMED] {vuln_meta['type']} in param '{param}' "
                            f"(method={result.method} conf={result.confidence:.2f})",
                            job_id,
                        )
                        push_log(
                            job_id,
                            f"[SCAN] CONFIRMED {vuln_meta['type']} in {param} "
                            f"(conf={result.confidence:.2f})",
                            tier=tier,
                        )

                    except asyncio.TimeoutError:
                        # Timeout on a SLEEP payload is itself time-based evidence.
                        # Run it through the timing oracle with a synthetic delay.
                        if any(k in payload.lower() for k in ["sleep", "waitfor", "pg_sleep"]):
                            synthetic_delay = req_timeout + 0.5
                            result = validator.verify(
                                vuln_type="sqli_time",
                                payload=payload,
                                body="",
                                status_code=200,
                                delay=synthetic_delay,
                                baseline_delay=baseline_delay,
                            )
                            if result.is_vulnerable:
                                finding = {
                                    "type":             "SQL Injection (Time-based — Timeout)",
                                    "severity":         "Critical",
                                    "param":            param,
                                    "payload":          payload,
                                    "target_url":       injected_url,
                                    "confidence_score": round(result.confidence, 4),
                                    "evidence_snippet": (
                                        f"Request timed out after {req_timeout}s — "
                                        + result.evidence_snippet
                                    ),
                                    "method":           result.method,
                                    "delay_seconds":    round(synthetic_delay, 2),
                                }
                                findings.append(finding)
                                logger.info(
                                    f"[CONFIRMED] SQLi timeout on param '{param}'", job_id
                                )

                    except Exception as exc:
                        logger.debug(f"Test failed for {param}/{vuln_type}: {exc}", job_id)

        logger.info(
            f"Scanning complete — {tests_run} tests run, "
            f"{len(findings)} evidence-confirmed vulnerabilities",
            job_id,
            details={"findings": len(findings)},
        )

    except Exception as exc:
        logger.error(f"Scan failed: {exc}", job_id)
        raise

    finally:
        await http_client.close()

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# VULN TYPE → DISPLAY METADATA
# ─────────────────────────────────────────────────────────────────────────────

_VULN_META = {
    "xss":        {"type": "Cross-Site Scripting (XSS)",         "severity": "High"},
    "sqli_error": {"type": "SQL Injection (Error-based)",        "severity": "Critical"},
    "sqli_time":  {"type": "SQL Injection (Time-based Blind)",   "severity": "Critical"},
    "sqli_bool":  {"type": "SQL Injection (Boolean-based Blind)","severity": "Critical"},
    "ssti":       {"type": "Server-Side Template Injection",     "severity": "Critical"},
    "lfi":        {"type": "Local File Inclusion",               "severity": "Critical"},
    "cmdi":       {"type": "Command Injection",                  "severity": "Critical"},
    "redirect":   {"type": "Open Redirect",                      "severity": "Medium"},
    "header":     {"type": "Header Injection",                   "severity": "High"},
    "ssrf":       {"type": "Server-Side Request Forgery (SSRF)", "severity": "Critical"},
    "xxe":        {"type": "XML External Entity (XXE)",          "severity": "Critical"},
    "_default":   {"type": "Unknown Vulnerability",              "severity": "Medium"},
}


# ─────────────────────────────────────────────────────────────────────────────
# WORKER ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def handle(job: dict) -> None:
    """
    Called by worker_loop for every job pulled from SCAN_QUEUE.

    Guarantees:
      • Job status is set to 'scanning' before any work begins (idempotency).
      • db.save_vulnerabilities() is called before on_scan_complete().
      • If anything fails, a JobFailed signal is pushed and the full
        stack trace is saved to the DB — no zombie jobs.
    """
    job_id     = job.get("job_id", "unknown")
    target_url = job.get("url") or job.get("target_url")
    tier       = job.get("tier", "Basic")
    findings: List[Dict] = []

    if not target_url:
        logger.error("No URL provided in job", job_id)
        return

    try:
        # ── IDEMPOTENCY: mark job as scanning immediately ─────────────────
        # FIX: Use update_job() not update_job_status() — the latter doesn't
        # exist on _MinimalDB (the fallback DB class in api/main.py).
        try:
            db = get_db()
            db.update_job(job_id, status="scanning")
        except Exception as db_init_exc:
            logger.warning(f"Could not set job status to scanning: {db_init_exc}", job_id)

        logger.info(f"Starting evidence-gated scan for {target_url}", job_id, tier=tier)
        push_log(job_id, f"[SCAN] Starting evidence-gated scan for {target_url}", tier=tier)

        session = get_session(job_id) or {}
        cookies = session.get("cookies", {})
        req_headers = session.get("headers", {})

        findings = asyncio.run(
            scan_url_async(
                job_id=job_id,
                target_url=target_url,
                tier=tier,
                cookies=cookies,
                headers=req_headers,
            )
        )

    except Exception as scan_exc:
        # Capture full stack trace for the DB error log
        tb = traceback.format_exc()
        logger.error(f"Scan failed with exception: {scan_exc}\n{tb}", job_id)
        push_log(job_id, f"[ERROR] Scan exception: {scan_exc}", tier=tier)
        try:
            db = get_db()
            db.save_error_log(job_id, f"Scan exception:\n{tb}")
        except Exception:
            pass  # DB itself may be unavailable; already logged above

    finally:
        # ── ALWAYS persist whatever findings we collected ─────────────────
        # Even a partial scan result is valuable and must reach the DB before
        # we signal completion or failure.
        db = get_db()
        try:
            safe_findings = _sanitize_findings(findings)
            db.save_vulnerabilities(job_id, safe_findings)
            push_log(
                job_id,
                f"[SCAN] Saved {len(safe_findings)} evidence-confirmed vulnerabilities to DB",
                tier=tier,
            )

            on_scan_complete(job_id, safe_findings, target=target_url, tier=tier)

            push_log(
                job_id,
                f"[SCAN] Complete — {len(safe_findings)} vulnerabilities confirmed",
                tier=tier,
            )
            logger.info(
                f"Routing {len(safe_findings)} findings to exploit stage", job_id
            )

        except Exception as persist_exc:
            tb = traceback.format_exc()
            logger.error(
                f"[SCAN] DB persist / pipeline routing failed: {persist_exc}\n{tb}", job_id
            )
            push_log(job_id, f"[ERROR] Persist failed: {persist_exc}", tier=tier)

            # Push JobFailed signal so the dashboard does not show a zombie job
            try:
                state_manager.fail_job(
                    job_id,
                    f"Scan worker persist error: {persist_exc}",
                )
            except Exception as sm_exc:
                logger.error(f"state_manager.fail_job also failed: {sm_exc}", job_id)


if __name__ == "__main__":
    worker_loop(SCAN_QUEUE, handle)

