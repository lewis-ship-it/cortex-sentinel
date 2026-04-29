# scanner/dast/modules/client_side.py
#
# ENHANCED CLIENT-SIDE MODULE — Deep XSS, Open Redirect, DOM Clobbering,
# Prototype Pollution, PostMessage abuse, CORS misconfiguration
# Uses context-aware payloads, WAF bypass mutations, and multi-verification

import asyncio
import logging
import re
import urllib.parse
import html as html_lib
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import httpx

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    "redirect_params": {
        "redirect", "next", "return", "dest", "destination", "url", "goto",
        "redir", "return_url", "callback", "target", "link", "forward",
        "location", "continue", "ref", "return_to", "redirect_uri", "redirect_url",
        "to", "route", "page", "view", "out", "exit", "away", "uri", "path",
    },
    "dom_reflect_params": {
        "q", "query", "search", "keyword", "s", "k", "term",
        "name", "user", "username", "email", "comment", "message",
        "input", "text", "value", "data", "content", "body",
        "title", "description", "label", "tag", "category", "id",
        "code", "filter", "sort", "order", "field", "select",
    },
    "max_payloads_per_param": 15,
    "max_mutations_per_payload": 6,
    "request_timeout": 15,
    "concurrent_requests": 5,
    "min_reflection_length": 3,
    "confidence_threshold": 0.7,
}

# Enhanced XSS payloads categorized by context
XSS_PAYLOADS_BY_CONTEXT = {
    "html": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
    ],
    "attribute": [
        "\" onload=alert(1) \"",
        "' onmouseover=alert(1) '",
        " onfocus=alert(1) autofocus ",
        " onerror=alert(1) ",
        " onscroll=alert(1) ",
        " oninput=alert(1) ",
    ],
    "javascript": [
        "javascript:alert(1)",
        "javascripT:alert(1)",
        "java%0ascript:alert(1)",
        "alert(1)",
        "confirm(1)",
        "prompt(1)",
        "eval('alert(1)')",
        "setTimeout('alert(1)',0)",
        "setInterval('alert(1)',0)",
    ],
    "url": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:alert(1)",
        "livescript:alert(1)",
    ]
}

# Open redirect payloads
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "\\evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "//attacker.com",
    "https://google.com",  # Benign but external
    "http://example.com",
]

class ClientSideModule:
    def __init__(self, scanner, config: Optional[Dict] = None):
        self.scanner = scanner
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.rate_limiter = asyncio.Semaphore(self.config["concurrent_requests"])

    async def run(self, client: httpx.AsyncClient, url: str, params: List[str]) -> None:
        """Run all client-side tests with enhanced error handling"""
        try:
            tasks = []
            for param in params:
                if param.lower() in self.config["redirect_params"]:
                    tasks.append(self.test_open_redirect(client, url, param))
                if param.lower() in self.config["dom_reflect_params"]:
                    tasks.append(self.test_xss(client, url, param))
                    tasks.append(self.test_dom_xss(client, url, param))
                
            # Global tests (not parameter-specific)
            tasks.append(self.test_cors(client, url))
            tasks.append(self.test_postmessage(client, url))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Log any exceptions
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Client-side test failed: {result}")
                    
        except Exception as e:
            logger.error(f"Client-side module failed for {url}: {e}")

    # ── Enhanced XSS Testing ──────────────────────────────────────────────────
    async def test_xss(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Comprehensive XSS testing with context detection"""
        try:
            # Phase 1: Detect reflection with canary
            canary = f"xss_test_{param}_{id(url) % 10000}"
            test_url = self._inject_param(url, param, canary)
            response = await self._safe_request(client, "GET", test_url)
            
            if not response or canary not in response.text:
                return  # No reflection detected
                
            # Phase 2: Detect context
            context = self._detect_context(response.text, canary)
            payloads = self._get_contextual_payloads(context)
            
            # Phase 3: Test with contextual payloads
            for payload in payloads[:self.config["max_payloads_per_param"]]:
                for mutated_payload in self._xss_mutations(payload)[:self.config["max_mutations_per_payload"]]:
                    if await self._test_xss_payload(client, url, param, mutated_payload, context):
                        return  # Stop after first successful detection
                        
        except Exception as e:
            logger.error(f"XSS test failed for {url} param {param}: {e}")

    def _detect_context(self, response_text: str, canary: str) -> str:
        """Detect the context where the canary is reflected"""
        # Find the position of the canary
        pos = response_text.find(canary)
        if pos == -1:
            return "unknown"
            
        # Extract surrounding context
        start = max(0, pos - 50)
        end = min(len(response_text), pos + len(canary) + 50)
        context = response_text[start:end]
        
        # Detect context type
        if re.search(r'<script[^>]*>.*' + canary, context, re.IGNORECASE):
            return "javascript"
        elif re.search(r'<[^>]+\s[^>]*' + canary, context, re.IGNORECASE):
            return "attribute"
        elif re.search(r'href=["\']?[^"\']*' + canary, context, re.IGNORECASE):
            return "url"
        elif re.search(r'<' + canary + r'[^>]*>', context, re.IGNORECASE):
            return "html"
        else:
            return "text"

    def _get_contextual_payloads(self, context: str) -> List[str]:
        """Get appropriate payloads for the detected context"""
        return XSS_PAYLOADS_BY_CONTEXT.get(context, XSS_PAYLOADS_BY_CONTEXT["html"])

    def _xss_mutations(self, payload: str) -> List[str]:
        """Generate WAF-bypass variants of an XSS payload"""
        mutations = [payload]
        
        # URL encoding variants
        mutations.append(urllib.parse.quote(payload))
        mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # HTML entity encoding
        mutations.append(payload.replace("<", "&lt;").replace(">", "&gt;"))
        mutations.append(payload.replace("<", "%3C").replace(">", "%3E"))
        
        # Case alternation
        if "script" in payload.lower():
            mutations.append(payload.replace("script", "ScRiPt"))
            mutations.append(payload.replace("script", "sCRipt"))
            
        # Whitespace variations
        if "<" in payload:
            mutations.append(payload.replace("<", "<\t"))
            mutations.append(payload.replace("<", "<\n"))
            mutations.append(payload.replace("<", "<\r"))
            
        # Null byte injection
        if any(keyword in payload.lower() for keyword in ["script", "on", "alert"]):
            mutated = payload.replace("script", "scri\x00pt")
            mutated = mutated.replace("onload", "on\x00load")
            mutations.append(mutated)
            
        # Unicode variations
        mutations.append(payload.replace("<", "\u003c").replace(">", "\u003e"))
        mutations.append(payload.replace("'", "\u0027").replace('"', "\u0022"))
        
        return list(set(mutations))  # Remove duplicates

    async def _test_xss_payload(self, client: httpx.AsyncClient, url: str, param: str, 
                              payload: str, context: str) -> bool:
        """Test a specific XSS payload"""
        test_url = self._inject_param(url, param, payload)
        response = await self._safe_request(client, "GET", test_url)
        
        if not response:
            return False
            
        # Check for exact reflection
        if payload in response.text:
            self._report_xss(url, param, payload, context, "exact", response)
            return True
            
        # Check for HTML-decoded reflection
        decoded = html_lib.unescape(payload)
        if decoded != payload and decoded in response.text:
            self._report_xss(url, param, payload, context, "html_decoded", response)
            return True
            
        # Check for dangerous fragments
        dangerous_patterns = [
            r"<script[^>]*>", r"onerror\s*=", r"onload\s*=", r"onclick\s*=",
            r"onfocus\s*=", r"onmouseover\s*=", r"javascript:",
            r"alert\(", r"confirm\(", r"prompt\(", r"eval\(",
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                self._report_xss(url, param, payload, context, "fragment", response)
                return True
                
        return False

    def _report_xss(self, url: str, param: str, payload: str, context: str, 
                   detection_type: str, response: httpx.Response) -> None:
        """Report XSS finding"""
        severity = "Critical" if context in ["html", "javascript"] else "High"
        confidence = 0.95 if detection_type == "exact" else 0.8
        
        self.scanner._add_finding({
            "type": "Cross-Site Scripting (XSS)",
            "subtype": f"Reflected ({context}) - {detection_type}",
            "url": url,
            "parameter": param,
            "payload": payload,
            "severity": severity,
            "confidence": confidence,
            "evidence": f"Payload reflected in {context} context",
            "description": f"Parameter '{param}' reflects unsanitized input in {context} context.",
        })

    # ── Enhanced DOM XSS Testing ──────────────────────────────────────────────
    async def test_dom_xss(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Comprehensive DOM-based XSS testing"""
        try:
            response = await self._safe_request(client, "GET", url)
            if not response:
                return
                
            # Check for DOM sinks
            dom_sinks = self._detect_dom_sinks(response.text)
            if not dom_sinks:
                return
                
            # Test DOM clobbering
            if await self._test_dom_clobbering(client, url, param):
                return
                
            # Test prototype pollution
            if await self._test_prototype_pollution(client, url, param):
                return
                
            # Test traditional DOM XSS
            await self._test_traditional_dom_xss(client, url, param, dom_sinks)
            
        except Exception as e:
            logger.error(f"DOM XSS test failed for {url}: {e}")

    def _detect_dom_sinks(self, html_content: str) -> List[str]:
        """Detect potential DOM sinks in HTML content"""
        sink_patterns = [
            r'\.innerHTML\s*=', r'\.outerHTML\s*=',
            r'document\.write\s*\(', r'document\.writeln\s*\(',
            r'\.insertAdjacentHTML\s*\(', r'\.insertAdjacentText\s*\(',
            r'eval\s*\(', r'setTimeout\s*\(["\']', r'setInterval\s*\(["\']',
            r'Function\s*\(', r'\.src\s*=\s*[^"\']*\+',
            r'location\s*=', r'location\.href\s*=',
            r'location\.search', r'location\.hash',
            r'document\.URL', r'document\.documentURI',
            r'document\.referrer', r'window\.name',
            r'\.setAttribute\s*\([^,]*,[^)]*\)',  # Potential for attribute XSS
        ]
        
        detected_sinks = []
        for pattern in sink_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                detected_sinks.append(pattern)
                
        return detected_sinks

    async def _test_dom_clobbering(self, client: httpx.AsyncClient, url: str, param: str) -> bool:
        """Test for DOM clobbering vulnerabilities"""
        clobbering_payloads = [
            f"<form id={param}><input name=attributes></form>",
            f"<a id={param} name=href></a>",
            f"<div id={param}><div name=parentNode></div></div>",
        ]
        
        for payload in clobbering_payloads:
            test_url = self._inject_param(url, param, payload)
            response = await self._safe_request(client, "GET", test_url)
            
            if response and payload in response.text:
                self.scanner._add_finding({
                    "type": "DOM Clobbering",
                    "subtype": f"Parameter: {param}",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "severity": "Medium",
                    "confidence": 0.75,
                    "evidence": "DOM clobbering payload reflected",
                    "description": f"Parameter '{param}' may be vulnerable to DOM clobbering attacks.",
                })
                return True
                
        return False

    async def _test_prototype_pollution(self, client: httpx.AsyncClient, url: str, param: str) -> bool:
        """Test for prototype pollution vulnerabilities"""
        pollution_payloads = [
            "__proto__.polluted=true",
            "constructor.prototype.polluted=true",
            "Object.prototype.polluted=true",
        ]
        
        for payload in pollution_payloads:
            test_url = self._inject_param(url, param, payload)
            response = await self._safe_request(client, "GET", test_url)
            
            if response and payload in response.text:
                self.scanner._add_finding({
                    "type": "Prototype Pollution",
                    "subtype": f"Parameter: {param}",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "severity": "High",
                    "confidence": 0.8,
                    "evidence": "Prototype pollution payload reflected",
                    "description": f"Parameter '{param}' may be vulnerable to prototype pollution attacks.",
                })
                return True
                
        return False

    async def _test_traditional_dom_xss(self, client: httpx.AsyncClient, url: str, 
                                      param: str, dom_sinks: List[str]) -> None:
        """Test traditional DOM XSS vulnerabilities"""
        dom_payloads = [
            "'><img src=x onerror=alert(1)>",
            "'><svg onload=alert(1)>",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
        
        for payload in dom_payloads:
            test_url = self._inject_param(url, param, payload)
            response = await self._safe_request(client, "GET", test_url)
            
            if response and payload in response.text:
                self.scanner._add_finding({
                    "type": "DOM-based XSS",
                    "subtype": f"Parameter: {param}",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "severity": "High",
                    "confidence": 0.85,
                    "evidence": f"DOM sink detected + payload reflection",
                    "description": f"Parameter '{param}' flows into a DOM sink without sanitization.",
                })
                return

    # ── Enhanced Open Redirect Testing ────────────────────────────────────────
    async def test_open_redirect(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Comprehensive open redirect testing"""
        try:
            base_host = urlparse(url).netloc
            
            for payload in OPEN_REDIRECT_PAYLOADS:
                for mutated_payload in self._redirect_mutations(payload):
                    test_url = self._inject_param(url, param, mutated_payload)
                    response = await self._safe_request(
                        client, "GET", test_url, follow_redirects=False
                    )
                    
                    if not response:
                        continue
                        
                    if self._is_redirect_vulnerable(response, base_host, mutated_payload):
                        self._report_open_redirect(url, param, mutated_payload, response)
                        return
                        
        except Exception as e:
            logger.error(f"Open redirect test failed for {url}: {e}")

    def _redirect_mutations(self, payload: str) -> List[str]:
        """Generate redirect payload variations"""
        mutations = [payload]
        
        # URL encoding
        mutations.append(urllib.parse.quote(payload))
        mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # Case variations
        if "javascript:" in payload.lower():
            mutations.append(payload.replace("javascript:", "javaScript:"))
            mutations.append(payload.replace("javascript:", "JAVASCRIPT:"))
            
        return mutations

    def _is_redirect_vulnerable(self, response: httpx.Response, base_host: str, payload: str) -> bool:
        """Determine if redirect response is vulnerable"""
        # Check HTTP redirect headers
        location = response.headers.get("location", "")
        if location and self._is_external_redirect(location, base_host):
            return True
            
        # Check meta refresh redirects
        if response.status_code == 200:
            meta_refresh = re.search(
                r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\'][^"\']*url=([^"\']+)',
                response.text, re.IGNORECASE
            )
            if meta_refresh and self._is_external_redirect(meta_refresh.group(1), base_host):
                return True
                
            # Check JavaScript redirects
            js_redirects = [
                r'window\.location\s*=\s*["\']([^"\']+)',
                r'window\.location\.href\s*=\s*["\']([^"\']+)',
                r'location\.replace\s*\(["\']([^"\']+)',
            ]
            
            for pattern in js_redirects:
                js_match = re.search(pattern, response.text, re.IGNORECASE)
                if js_match and self._is_external_redirect(js_match.group(1), base_host):
                    return True
                    
        return False

    def _is_external_redirect(self, target: str, base_host: str) -> bool:
        """Check if redirect target is external"""
        try:
            target_host = urlparse(target).netloc
            # Handle protocol-relative URLs
            if target.startswith("//"):
                return True
            # Handle JavaScript URLs
            if target.lower().startswith("javascript:"):
                return True
            # Handle data URLs
            if target.lower().startswith("data:"):
                return True
            # Handle different hosts
            if target_host and target_host != base_host:
                return True
        except Exception:
            pass
            
        return False

    def _report_open_redirect(self, url: str, param: str, payload: str, response: httpx.Response) -> None:
        """Report open redirect finding"""
        location = response.headers.get("location", "")
        evidence = f"Location: {location}" if location else "Meta/JS redirect detected"
        
        self.scanner._add_finding({
            "type": "Open Redirect",
            "subtype": "Unvalidated Redirect",
            "url": url,
            "parameter": param,
            "payload": payload,
            "severity": "Medium",
            "confidence": 0.9,
            "evidence": evidence,
            "description": f"Parameter '{param}' allows unvalidated redirects to external URLs.",
        })

    # ── Enhanced CORS Testing ─────────────────────────────────────────────────
    async def test_cors(self, client: httpx.AsyncClient, url: str) -> None:
        """Comprehensive CORS misconfiguration testing"""
        try:
            test_origins = [
                "https://evil.com",
                "http://attacker.net",
                "null",
                "https://" + urlparse(url).netloc,  # Same origin different scheme
                "https://subdomain.evil.com",
            ]
            
            for origin in test_origins:
                if await self._test_cors_origin(client, url, origin):
                    return
                    
            # Test pre-flight requests
            await self._test_cors_preflight(client, url)
            
        except Exception as e:
            logger.error(f"CORS test failed for {url}: {e}")

    async def _test_cors_origin(self, client: httpx.AsyncClient, url: str, origin: str) -> bool:
        """Test CORS for a specific origin"""
        try:
            response = await self._safe_request(
                client, "GET", url, 
                headers={"Origin": origin},
                follow_redirects=True
            )
            
            if not response:
                return False
                
            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "").lower()
            
            # Wildcard with credentials (invalid but sometimes implemented)
            if acao == "*" and acac == "true":
                self._report_cors_misconfig(url, origin, "Wildcard with credentials", acao, acac)
                return True
                
            # Reflected origin with credentials
            if acao == origin and acac == "true":
                self._report_cors_misconfig(url, origin, "Reflected origin with credentials", acao, acac)
                return True
                
            # Reflected origin without credentials
            if acao == origin and acac != "true":
                self._report_cors_misconfig(url, origin, "Reflected origin", acao, acac)
                return True
                
            # Null origin
            if acao == "null":
                self._report_cors_misconfig(url, origin, "Null origin", acao, acac)
                return True
                
        except Exception as e:
            logger.debug(f"CORS origin test failed for {origin}: {e}")
            
        return False

    async def _test_cors_preflight(self, client: httpx.AsyncClient, url: str) -> None:
        """Test CORS pre-flight requests"""
        try:
            response = await self._safe_request(
                client, "OPTIONS", url,
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "x-custom-header"
                }
            )
            
            if response and response.status_code == 200:
                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "").lower()
                acam = response.headers.get("access-control-allow-methods", "")
                acah = response.headers.get("access-control-allow-headers", "")
                
                if acao == "*" or acao == "https://evil.com":
                    self._report_cors_misconfig(url, "https://evil.com", "Pre-flight vulnerable", acao, acac)
                    
        except Exception as e:
            logger.debug(f"CORS pre-flight test failed: {e}")

    def _report_cors_misconfig(self, url: str, origin: str, subtype: str, 
                             acao: str, acac: str) -> None:
        """Report CORS misconfiguration"""
        severity = "Critical" if "credentials" in subtype else "High"
        
        self.scanner._add_finding({
            "type": "CORS Misconfiguration",
            "subtype": subtype,
            "url": url,
            "parameter": "CORS",
            "payload": f"Origin: {origin}",
            "severity": severity,
            "confidence": 0.95,
            "evidence": f"ACAO={acao}, ACAC={acac}",
            "description": f"CORS misconfiguration allows cross-origin requests from {origin}.",
        })

    # ── PostMessage Testing ───────────────────────────────────────────────────
    async def test_postmessage(self, client: httpx.AsyncClient, url: str) -> None:
        """Test for PostMessage vulnerabilities"""
        try:
            response = await self._safe_request(client, "GET", url)
            if not response:
                return
                
            # Check for PostMessage usage
            if not self._detect_postmessage_usage(response.text):
                return
                
            self.scanner._add_finding({
                "type": "PostMessage Vulnerability",
                "subtype": "Usage Detected",
                "url": url,
                "severity": "Low",
                "confidence": 0.7,
                "evidence": "PostMessage API usage detected",
                "description": "PostMessage API detected. Review for proper origin validation.",
            })
            
        except Exception as e:
            logger.error(f"PostMessage test failed for {url}: {e}")

    def _detect_postmessage_usage(self, html_content: str) -> bool:
        """Detect PostMessage API usage"""
        patterns = [
            r'window\.postMessage\s*\(',
            r'window\.addEventListener\s*\(["\']message["\']',
            r'\.onmessage\s*=',
        ]
        
        return any(re.search(pattern, html_content, re.IGNORECASE) for pattern in patterns)

    # ── Utility Methods ───────────────────────────────────────────────────────
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
