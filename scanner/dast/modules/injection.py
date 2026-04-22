# scanner/dast/modules/injection.py
#
# FIXES:
#   - Removed import of utils.evasion (now imported gracefully)
#   - Removed self.scanner.redis (canaries stored in canary_map dict instead)
#   - Added baseline comparison for time-based SQLi
#   - Added full SSTI detection
#   - Added form injection test method

import asyncio
import logging
import os
import time

from scanner.dast.payloads import (
    SQLI_PAYLOADS, SQLI_ERROR_SIGNATURES,
    CMDI_PAYLOADS, SSTI_PAYLOADS, LFI_PAYLOADS,
)

try:
    from utils.evasion import EvasionUtility
    _evasion = EvasionUtility()
except ImportError:
    class _FallbackEvasion:
        def apply_stealth(self, p, level=1): return p
    _evasion = _FallbackEvasion()

logger = logging.getLogger(__name__)

CMDI_OUTPUT_MARKERS = [
    "root:x:", "root:0:0", "daemon:", "bin/bash", "bin/sh",
    "uid=", "gid=", "groups=", "www-data",
    "Windows IP Configuration", "Microsoft Windows",
    "[boot loader]", "[fonts]",
]


class InjectionModule:
    def __init__(self, scanner):
        self.scanner = scanner

    async def run(self, client, url: str, params: list) -> None:
        for param in params:
            context = await self.scanner._get_context(client, url, param)

            # Register second-order canary (stored in dict, not Redis)
            canary = f"canary_{param}_{os.urandom(3).hex()}"
            self.scanner.canary_map[canary] = {"url": url, "param": param}
            canary_url = self.scanner.param_engine.inject_payload(url, param, canary)
            await self.scanner._req(client, "GET", canary_url)

            await asyncio.gather(
                self.test_sqli(client, url, param, context),
                self.test_cmdi(client, url, param),
                self.test_ssti(client, url, param),
                self.test_lfi(client, url, param),
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

        for raw_payload in SQLI_PAYLOADS:
            payload  = _evasion.apply_stealth(raw_payload, level=1)
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            res      = await self.scanner._req(client, "GET", test_url)
            if not res:
                continue

            # A. Error-based
            body = res.text.lower()
            for sig in SQLI_ERROR_SIGNATURES:
                if sig in body:
                    self.scanner._add_finding({
                        "type": "SQL Injection", "subtype": "Error-Based",
                        "url": test_url, "parameter": param, "payload": payload,
                        "severity": "Critical", "confidence": 0.95,
                        "evidence": f"DB error: '{sig}'",
                        "description": f"Parameter '{param}' reflects a SQL error — unsanitised input reaches the DB.",
                    })
                    return

            # B. Boolean-based blind
            if "1=1" in raw_payload:
                f_url = self.scanner.param_engine.inject_payload(url, param, raw_payload.replace("1=1", "1=2"))
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

            # C. Time-based blind
            if any(k in payload.upper() for k in ("SLEEP", "WAITFOR", "BENCHMARK", "PG_SLEEP")):
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
            ("; whoami", ["root", "www-data", "apache", "nginx"]),
            ("| id", ["uid=", "gid=", "groups="]),
        ]
        for payload, markers in output_payloads:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            res = await self.scanner._req(client, "GET", test_url)
            if res:
                for m in markers:
                    if m in res.text:
                        self.scanner._add_finding({
                            "type": "Command Injection", "subtype": "Output-Based",
                            "url": test_url, "parameter": param, "payload": payload,
                            "severity": "Critical", "confidence": 0.97,
                            "evidence": f"OS output marker: '{m}'",
                            "description": f"Parameter '{param}' executes arbitrary OS commands.",
                        })
                        return

        # Time-based blind fallback
        t0       = asyncio.get_event_loop().time()
        baseline = await self.scanner._req(client, "GET", url)
        base_lat = asyncio.get_event_loop().time() - t0

        for payload in ["; sleep 5; #", "| sleep 5", "$(sleep 5)"]:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            t_start  = asyncio.get_event_loop().time()
            await self.scanner._req(client, "GET", test_url, timeout=20)
            elapsed  = asyncio.get_event_loop().time() - t_start
            if elapsed >= base_lat + 4.0:
                self.scanner._add_finding({
                    "type": "Command Injection", "subtype": "Time-Based Blind",
                    "url": test_url, "parameter": param, "payload": payload,
                    "severity": "Critical", "confidence": 0.88,
                    "evidence": f"Baseline={base_lat:.2f}s  Attack={elapsed:.2f}s",
                    "description": f"Parameter '{param}' caused a {elapsed:.2f}s delay — blind CMDI.",
                })
                return

    # ── SSTI ──────────────────────────────────────────────────────────────────
    async def test_ssti(self, client, url: str, param: str) -> None:
        url1 = self.scanner.param_engine.inject_payload(url, param, "{{7*7}}")
        r1   = await self.scanner._req(client, "GET", url1)
        if not (r1 and "49" in r1.text):
            return
        url2 = self.scanner.param_engine.inject_payload(url, param, "{{3*3}}")
        r2   = await self.scanner._req(client, "GET", url2)
        if r2 and "9" in r2.text:
            self.scanner._add_finding({
                "type": "Server-Side Template Injection (SSTI)", "subtype": "Confirmed",
                "url": url1, "parameter": param, "payload": "{{7*7}}",
                "severity": "Critical", "confidence": 0.93,
                "evidence": "{{7*7}}→49 and {{3*3}}→9 confirmed",
                "description": f"Parameter '{param}' evaluates template expressions — RCE likely.",
            })

    # ── LFI ───────────────────────────────────────────────────────────────────
    async def test_lfi(self, client, url: str, param: str) -> None:
        LFI_INDICATORS = [
            "root:x:", "root:0:0", "daemon:", "nobody:", "bin/bash",
            "www-data", "[boot loader]", "[fonts]",
        ]
        for payload in LFI_PAYLOADS:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            res = await self.scanner._req(client, "GET", test_url)
            if res:
                for ind in LFI_INDICATORS:
                    if ind in res.text:
                        self.scanner._add_finding({
                            "type": "Local File Inclusion (LFI)", "subtype": "Path Traversal",
                            "url": test_url, "parameter": param, "payload": payload,
                            "severity": "Critical", "confidence": 0.95,
                            "evidence": f"File marker '{ind}' in response",
                            "description": f"Parameter '{param}' allows reading server files.",
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

        for payload in SQLI_PAYLOADS[:12]:
            data = {k: payload for k in base}
            res  = await _send(data)
            if not res:
                continue
            body = res.text.lower()
            for sig in SQLI_ERROR_SIGNATURES:
                if sig in body:
                    self.scanner._add_finding({
                        "type": "SQL Injection", "subtype": f"Error-Based via Form ({method})",
                        "url": url, "parameter": "form", "payload": payload,
                        "severity": "Critical", "confidence": 0.95,
                        "evidence": f"DB error: '{sig}'",
                        "description": f"Form at {url} passes unsanitised input to the DB.",
                    })
                    return