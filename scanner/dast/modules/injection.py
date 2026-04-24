# scanner/dast/modules/injection.py
#
# AGGRESSIVE INJECTION MODULE — Multi-strategy, multi-encoding, multi-database
# Tests: SQLi (error/union/boolean/time/stacked/NoSQL), CMDI, SSTI, LFI, XXE
# Each test uses WAF bypass mutations and context-aware payload selection.

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

logger = logging.getLogger(__name__)

CMDI_OUTPUT_MARKERS = [
    "root:x:", "root:0:0", "daemon:", "bin/bash", "bin/sh",
    "uid=", "gid=", "groups=", "www-data",
    "Windows IP Configuration", "Microsoft Windows",
    "[boot loader]", "[fonts]", "SENTINEL_CMDI",
]

# WAF bypass mutation strategies
def _apply_mutations(payload: str) -> list:
    """Generate WAF-bypass variants of a payload."""
    variants = [payload]
    # URL encoding
    variants.append(urllib.parse.quote(payload))
    # Double URL encoding
    variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
    # Case alternation
    if any(c.isalpha() for c in payload):
        mangled = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        variants.append(mangled)
    # SQL comment breaking
    if "SELECT" in payload.upper():
        variants.append(re.sub(r'SELECT', 'SE/**/LECT', payload, flags=re.IGNORECASE))
    if "UNION" in payload.upper():
        variants.append(re.sub(r'UNION', 'UN/**/ION', payload, flags=re.IGNORECASE))
    if "OR" in payload.upper() and "OR" not in "ORDER":
        variants.append(payload.replace("OR", "/**/OR/**/").replace("or", "/**/or/**/"))
    # Space replacement
    variants.append(payload.replace(" ", "/**/"))
    variants.append(payload.replace(" ", "+"))
    variants.append(payload.replace(" ", "%09"))
    # Null byte in keywords
    if "<script" in payload.lower():
        variants.append(payload.replace("script", "scri\x00pt"))
    return variants[:8]  # cap to avoid explosion


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
            # Apply WAF bypass mutations
            for payload in _apply_mutations(raw_payload):
                test_url = self.scanner.param_engine.inject_payload(url, param, payload)
                res = await self.scanner._req(client, "GET", test_url)
                if not res:
                    continue

                # A. Error-based
                body = res.text.lower()
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig.lower() in body:
                        self.scanner._add_finding({
                            "type": "SQL Injection", "subtype": "Error-Based",
                            "url": test_url, "parameter": param, "payload": payload,
                            "severity": "Critical", "confidence": 0.95,
                            "evidence": f"DB error: '{sig}'",
                            "description": f"Parameter '{param}' reflects a SQL error — unsanitised input reaches the DB.",
                        })
                        return

                # B. Union-based (look for numeric column markers)
                if "UNION" in payload.upper() and "SELECT" in payload.upper():
                    # Check if response differs significantly from baseline
                    if abs(len(res.text) - len(baseline_text)) > 200:
                        # Look for column number markers (1, 2, 3...)
                        for i in range(1, 10):
                            marker = f"SENTINEL_COL_{i}"
                            if marker in res.text:
                                self.scanner._add_finding({
                                    "type": "SQL Injection", "subtype": "Union-Based",
                                    "url": test_url, "parameter": param, "payload": payload,
                                    "severity": "Critical", "confidence": 0.93,
                                    "evidence": f"UNION SELECT returned data — column {i} visible",
                                    "description": f"Parameter '{param}' allows UNION-based data extraction.",
                                })
                                return

                # C. Boolean-based blind
                if "1=1" in raw_payload or "' OR '" in raw_payload:
                    f_payload = raw_payload.replace("1=1", "1=2").replace("' OR '", "' AND '")
                    f_url = self.scanner.param_engine.inject_payload(url, param, f_payload)
                    f_res = await self.scanner._req(client, "GET", f_url)
                    if f_res:
                        diff = abs(len(res.text) - len(f_res.text))
                        if diff > 50:
                            self.scanner._add_finding({
                                "type": "SQL Injection", "subtype": "Boolean-Based Blind",
                                "url": test_url, "parameter": param, "payload": payload,
                                "severity": "Critical", "confidence": 0.82,
                                "evidence": f"True/false response diff: {diff} bytes",
                                "description": f"Parameter '{param}' behaves differently for true/false SQL conditions.",
                            })
                            return

                # D. Time-based blind
                if any(k in payload.upper() for k in ("SLEEP", "WAITFOR", "BENCHMARK", "PG_SLEEP", "DBMS_PIPE")):
                    t_start = asyncio.get_event_loop().time()
                    await self.scanner._req(client, "GET", test_url, timeout=15)
                    elapsed = asyncio.get_event_loop().time() - t_start
                    if elapsed >= base_lat + 3.0:
                        self.scanner._add_finding({
                            "type": "SQL Injection", "subtype": "Time-Based Blind",
                            "url": test_url, "parameter": param, "payload": payload,
                            "severity": "Critical", "confidence": 0.88,
                            "evidence": f"Baseline={base_lat:.2f}s  Attack={elapsed:.2f}s",
                            "description": f"Parameter '{param}' caused a {elapsed:.2f}s delay — time-based blind SQLi.",
                        })
                        return

    # ── Command Injection ─────────────────────────────────────────────────────
    async def test_cmdi(self, client, url: str, param: str) -> None:
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
            # Windows
            ("& dir", ["Volume Serial", "Directory of"]),
            ("| dir", ["Volume Serial", "Directory of"]),
        ]
        for payload, markers in output_payloads:
            for mutated in _apply_mutations(payload)[:3]:
                test_url = self.scanner.param_engine.inject_payload(url, param, mutated)
                res = await self.scanner._req(client, "GET", test_url)
                if res:
                    for m in markers:
                        if m in res.text:
                            self.scanner._add_finding({
                                "type": "Command Injection", "subtype": "Output-Based",
                                "url": test_url, "parameter": param, "payload": mutated,
                                "severity": "Critical", "confidence": 0.97,
                                "evidence": f"OS output marker: '{m}'",
                                "description": f"Parameter '{param}' executes arbitrary OS commands.",
                            })
                            return

        # Time-based blind fallback
        t0       = asyncio.get_event_loop().time()
        baseline = await self.scanner._req(client, "GET", url)
        base_lat = asyncio.get_event_loop().time() - t0

        for payload in ["; sleep 6; #", "| sleep 6", "$(sleep 6)", "`sleep 6`"]:
            for mutated in _apply_mutations(payload)[:2]:
                test_url = self.scanner.param_engine.inject_payload(url, param, mutated)
                t_start  = asyncio.get_event_loop().time()
                await self.scanner._req(client, "GET", test_url, timeout=20)
                elapsed  = asyncio.get_event_loop().time() - t_start
                if elapsed >= base_lat + 4.0:
                    self.scanner._add_finding({
                        "type": "Command Injection", "subtype": "Time-Based Blind",
                        "url": test_url, "parameter": param, "payload": mutated,
                        "severity": "Critical", "confidence": 0.88,
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
            # Try other template engines
            for payload in ["${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}"]:
                test_url = self.scanner.param_engine.inject_payload(url, param, payload)
                res = await self.scanner._req(client, "GET", test_url)
                if res and "49" in res.text:
                    self.scanner._add_finding({
                        "type": "Server-Side Template Injection (SSTI)", "subtype": "Confirmed",
                        "url": test_url, "parameter": param, "payload": payload,
                        "severity": "Critical", "confidence": 0.90,
                        "evidence": f"{payload} evaluated to 49",
                        "description": f"Parameter '{param}' evaluates template expressions — RCE likely.",
                    })
                    return
            return

        # Phase 2: Confirm with different oracle
        url2 = self.scanner.param_engine.inject_payload(url, param, "{{3*3}}")
        r2   = await self.scanner._req(client, "GET", url2)
        if r2 and "9" in r2.text:
            self.scanner._add_finding({
                "type": "Server-Side Template Injection (SSTI)", "subtype": "Confirmed",
                "url": url1, "parameter": param, "payload": "{{7*7}}",
                "severity": "Critical", "confidence": 0.93,
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
        # Get baseline to avoid false positives
        baseline = await self.scanner._req(client, "GET", url)
        baseline_text = baseline.text if baseline else ""

        for payload in LFI_PAYLOADS:
            for mutated in _apply_mutations(payload)[:3]:
                test_url = self.scanner.param_engine.inject_payload(url, param, mutated)
                res = await self.scanner._req(client, "GET", test_url)
                if res:
                    for ind in LFI_INDICATORS:
                        if ind in res.text and (not baseline_text or ind not in baseline_text):
                            self.scanner._add_finding({
                                "type": "Local File Inclusion (LFI)", "subtype": "Path Traversal",
                                "url": test_url, "parameter": param, "payload": mutated,
                                "severity": "Critical", "confidence": 0.95,
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
        for payload in XXE_PAYLOADS[:5]:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            res = await self.scanner._req(client, "GET", test_url)
            if res:
                for ind in XXE_INDICATORS:
                    if ind in res.text:
                        self.scanner._add_finding({
                            "type": "XML External Entity (XXE)", "subtype": "File Disclosure",
                            "url": test_url, "parameter": param, "payload": payload[:80],
                            "severity": "Critical", "confidence": 0.95,
                            "evidence": f"XXE indicator '{ind}' in response",
                            "description": f"Parameter '{param}' processes XML external entities.",
                        })
                        return

    # ── NoSQL Injection ──────────────────────────────────────────────────────
    async def test_nosql(self, client, url: str, param: str) -> None:
        for payload in NOSQL_PAYLOADS:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            res = await self.scanner._req(client, "GET", test_url)
            if not res:
                continue
            # NoSQL errors or unexpected behavior
            nosql_errors = [
                "mongo", "mongodb", "mongod", "no sql",
                "$where", "$gt", "$ne", "$regex",
                "syntax error", "unexpected token",
            ]
            body_lower = res.text.lower()
            for err in nosql_errors:
                if err in body_lower:
                    self.scanner._add_finding({
                        "type": "NoSQL Injection", "subtype": "Operator Injection",
                        "url": test_url, "parameter": param, "payload": payload[:60],
                        "severity": "Critical", "confidence": 0.85,
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
                        self.scanner._add_finding({
                            "type": "SQL Injection", "subtype": f"Error-Based via Form ({method})",
                            "url": url, "parameter": "form", "payload": mutated,
                            "severity": "Critical", "confidence": 0.95,
                            "evidence": f"DB error: '{sig}'",
                            "description": f"Form at {url} passes unsanitised input to the DB.",
                        })
                        return

        # NoSQL via form
        for payload in NOSQL_PAYLOADS[:4]:
            data = {k: payload for k in base}
            res = await _send(data)
            if res:
                for err in ["mongo", "$where", "$gt", "$ne"]:
                    if err in res.text.lower():
                        self.scanner._add_finding({
                            "type": "NoSQL Injection", "subtype": f"Form ({method})",
                            "url": url, "parameter": "form", "payload": payload[:60],
                            "severity": "Critical", "confidence": 0.85,
                            "evidence": f"NoSQL indicator: '{err}'",
                            "description": f"Form at {url} may allow NoSQL injection.",
                        })
                        return
