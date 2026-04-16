# scanner/dast/modules/infra.py
#
# IMPROVEMENTS:
#   - SSRF now also checks internal services (Redis, Elasticsearch, MongoDB)
#   - LFI has OS-specific detection (Windows + Linux)
#   - OAST payload injected when OAST is active

import asyncio
import logging
from scanner.dast.payloads import LFI_PAYLOADS, SSRF_PAYLOADS

logger = logging.getLogger(__name__)

SSRF_PROBE_PARAMS = frozenset({
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "path", "fetch", "load", "file", "resource",
    "host", "target", "endpoint", "proxy", "request", "href", "callback",
})

SSRF_TARGETS = [
    # Cloud metadata
    ("AWS",           "http://169.254.169.254/latest/meta-data/",                {}),
    ("GCP",           "http://metadata.google.internal/computeMetadata/v1/",     {"Metadata-Flavor": "Google"}),
    ("DigitalOcean",  "http://169.254.169.254/metadata/v1/",                     {}),
    # Internal services
    ("Redis",         "http://127.0.0.1:6379",                                   {}),
    ("Elasticsearch", "http://127.0.0.1:9200",                                   {}),
    ("MongoDB",       "http://127.0.0.1:27017",                                  {}),
    ("Internal",      "http://localhost:80",                                      {}),
    ("IPv6 Local",    "http://[::1]",                                             {}),
    ("Decimal IP",    "http://2130706433",                                        {}),  # 127.0.0.1
]

SSRF_INDICATORS = [
    "ami-id", "instance-id", "iam/security-credentials", "local-ipv4",
    "computeMetadata", "-ERR", "+PONG", "+OK",
    "mongodb", "elasticsearch", "localhost",
]

LFI_INDICATORS = [
    "root:x:", "root:0:0", "daemon:", "nobody:", "bin/bash", "bin/sh",
    "www-data", "[boot loader]", "[fonts]",
]


class InfraModule:
    def __init__(self, scanner):
        self.scanner = scanner

    async def run(self, client, url: str, params: list) -> None:
        tasks = []
        for param in params:
            tasks.append(self.test_lfi(client, url, param))
            tasks.append(self.test_ssrf(client, url, param))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def test_ssrf(self, client, url: str, param: str) -> None:
        if param.lower() not in SSRF_PROBE_PARAMS:
            return

        # OAST blind detection (if configured)
        if self.scanner.oast:
            oast_url  = f"http://{self.scanner.oast.domain}/ssrf_{param}"
            probe_url = self.scanner.param_engine.inject_payload(url, param, oast_url)
            await self.scanner._req(client, "GET", probe_url, timeout=8)

        # Inline response-based detection
        for provider, target, extra_headers in SSRF_TARGETS:
            test_url = self.scanner.param_engine.inject_payload(url, param, target)
            res = await self.scanner._req(client, "GET", test_url, headers=extra_headers, timeout=8)
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
        for payload in LFI_PAYLOADS:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            res = await self.scanner._req(client, "GET", test_url)
            if not res:
                continue
            for ind in LFI_INDICATORS:
                if ind in res.text:
                    self.scanner._add_finding({
                        "type": "Local File Inclusion (LFI)", "subtype": "Path Traversal",
                        "url": test_url, "parameter": param, "payload": payload,
                        "severity": "Critical", "confidence": 0.95,
                        "evidence": f"File marker '{ind}' found",
                        "description": f"Parameter '{param}' allows reading server files via path traversal.",
                    })
                    return
