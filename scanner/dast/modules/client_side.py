# scanner/dast/modules/client_side.py
#
# AGGRESSIVE CLIENT-SIDE MODULE — Deep XSS, Open Redirect, DOM Clobbering,
# Prototype Pollution, PostMessage abuse, CORS misconfiguration
# Uses context-aware payloads, WAF bypass mutations, and multi-verification

import asyncio
import logging
import re
import urllib.parse
from urllib.parse import urlparse
from scanner.dast.payloads import XSS_PAYLOADS, OPEN_REDIRECT_PAYLOADS

logger = logging.getLogger(__name__)

REDIRECT_PARAMS = frozenset({
    "redirect", "next", "return", "dest", "destination", "url", "goto",
    "redir", "return_url", "callback", "target", "link", "forward",
    "location", "continue", "ref", "return_to", "redirect_uri", "redirect_url",
    "to", "route", "page", "view", "out", "exit", "away",
})

# Parameters likely to reflect in DOM
DOM_REFLECT_PARAMS = frozenset({
    "q", "query", "search", "keyword", "s", "k", "term",
    "name", "user", "username", "email", "comment", "message",
    "input", "text", "value", "data", "content", "body",
    "title", "description", "label", "tag", "category",
})


def _xss_mutations(payload: str) -> list:
    """Generate WAF-bypass variants of an XSS payload."""
    variants = [payload]
    # URL encoding
    variants.append(urllib.parse.quote(payload))
    # Double URL encoding
    variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
    # HTML entity encoding for angle brackets
    variants.append(payload.replace("<", "%3C").replace(">", "%3E"))
    # Case alternation
    if "<script" in payload.lower():
        variants.append(payload.replace("script", "ScRiPt"))
    # Tab/newline in tag
    if "<" in payload:
        variants.append(payload.replace("<", "<\t"))
        variants.append(payload.replace("<", "<\n"))
    # Null byte
    if "script" in payload.lower():
        variants.append(payload.replace("script", "scri\x00pt"))
    # Unicode
    variants.append(payload.replace("<", "\u003c").replace(">", "\u003e"))
    return variants[:6]


class ClientSideModule:
    def __init__(self, scanner):
        self.scanner = scanner

    async def run(self, client, url: str, params: list) -> None:
        tasks = []
        for param in params:
            tasks.append(self.test_xss(client, url, param))
            tasks.append(self.test_open_redirect(client, url, param))
            tasks.append(self.test_dom_xss(client, url, param))
            tasks.append(self.test_cors(client, url, param))
        await asyncio.gather(*tasks, return_exceptions=True)

    # ── XSS ───────────────────────────────────────────────────────────────────
    async def test_xss(self, client, url: str, param: str) -> None:
        # Phase 1: detect context with neutral canary
        context = await self.scanner._get_context(client, url, param)
        payloads = self.scanner.context_engine.get_payloads(context)
        if not payloads:
            payloads = XSS_PAYLOADS

        # Phase 2: verify reflection with canary
        canary = f"ctx_{param}_{id(url) % 10000}"
        c_url  = self.scanner.param_engine.inject_payload(url, param, canary)
        c_res  = await self.scanner._req(client, "GET", c_url)
        if not c_res or canary not in c_res.text:
            return  # no reflection — skip

        # Phase 3: attack with targeted payloads + mutations
        for payload in payloads:
            for mutated in _xss_mutations(payload):
                test_url = self.scanner.param_engine.inject_payload(url, param, mutated)
                res = await self.scanner._req(client, "GET", test_url)
                if not res:
                    continue

                # Check for exact reflection (highest confidence)
                if mutated in res.text:
                    self.scanner._add_finding({
                        "type": "Cross-Site Scripting (XSS)", "subtype": f"Reflected ({context})",
                        "url": test_url, "parameter": param, "payload": mutated,
                        "severity": "High" if context == "html" else "Critical",
                        "confidence": 0.95,
                        "evidence": f"Payload reflected verbatim in '{context}' context",
                        "description": f"Parameter '{param}' reflects unsanitised input in {context} context.",
                    })
                    return

                # Check for partial reflection (dangerous fragments)
                dangerous_fragments = [
                    "<script", "onerror=", "onload=", "onclick=",
                    "onfocus=", "onmouseover=", "javascript:",
                    "alert(", "confirm(", "prompt(",
                ]
                for frag in dangerous_fragments:
                    if frag.lower() in mutated.lower() and frag.lower() in res.text.lower():
                        self.scanner._add_finding({
                            "type": "Cross-Site Scripting (XSS)", "subtype": f"Partial Reflection ({context})",
                            "url": test_url, "parameter": param, "payload": mutated,
                            "severity": "High",
                            "confidence": 0.80,
                            "evidence": f"Dangerous fragment '{frag}' reflected in '{context}' context",
                            "description": f"Parameter '{param}' partially reflects dangerous input.",
                        })
                        return

                # Check for HTML-decoded reflection
                import html as _html
                decoded = _html.unescape(mutated)
                if decoded != mutated and decoded in res.text:
                    self.scanner._add_finding({
                        "type": "Cross-Site Scripting (XSS)", "subtype": f"HTML-Decoded Reflection ({context})",
                        "url": test_url, "parameter": param, "payload": mutated,
                        "severity": "High",
                        "confidence": 0.85,
                        "evidence": f"Payload reflected after HTML decode in '{context}' context",
                        "description": f"Parameter '{param}' reflects HTML-decoded input.",
                    })
                    return

    # ── DOM-based XSS ─────────────────────────────────────────────────────────
    async def test_dom_xss(self, client, url: str, param: str) -> None:
        """Test for DOM-based XSS by checking if JS sources read the parameter."""
        if param.lower() not in DOM_REFLECT_PARAMS and param.lower() not in REDIRECT_PARAMS:
            return

        # Check if the page source contains DOM sinks
        res = await self.scanner._req(client, "GET", url)
        if not res:
            return

        dom_sinks = [
            r'\.innerHTML\s*=', r'\.outerHTML\s*=',
            r'document\.write\s*\(', r'document\.writeln\s*\(',
            r'\.insertAdjacentHTML\s*\(',
            r'eval\s*\(', r'setTimeout\s*\(["\']',
            r'location\s*=', r'location\.href\s*=',
            r'location\.search', r'location\.hash',
            r'document\.URL', r'document\.documentURI',
            r'document\.referrer', r'window\.name',
            r'\.src\s*=\s*[^"\']*\+',  # dynamic src assignment
        ]

        has_sink = False
        for sink in dom_sinks:
            if re.search(sink, res.text):
                has_sink = True
                break

        if not has_sink:
            return

        # If there's a DOM sink, try injecting into the parameter
        dom_payloads = [
            f"'><img src=x onerror=alert(1)>",
            f"'><svg/onload=alert(1)>",
            f"'><script>alert(1)</script>",
            f"'><iframe src=javascript:alert(1)>",
            f"jaVasCript:alert(1)//",
        ]
        for payload in dom_payloads:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            res2 = await self.scanner._req(client, "GET", test_url)
            if res2 and payload in res2.text:
                self.scanner._add_finding({
                    "type": "Cross-Site Scripting (XSS)", "subtype": "DOM-Based",
                    "url": test_url, "parameter": param, "payload": payload,
                    "severity": "High", "confidence": 0.85,
                    "evidence": f"DOM sink + parameter reflection — payload in page source",
                    "description": f"Parameter '{param}' flows into a DOM sink without sanitization.",
                })
                return

    # ── Open Redirect ─────────────────────────────────────────────────────────
    async def test_open_redirect(self, client, url: str, param: str) -> None:
        if param.lower() not in REDIRECT_PARAMS:
            return

        base_host = urlparse(url).netloc

        for payload in OPEN_REDIRECT_PAYLOADS:
            for mutated in [payload, urllib.parse.quote(payload)]:
                test_url = self.scanner.param_engine.inject_payload(url, param, mutated)
                try:
                    res = await client.get(test_url, follow_redirects=False, timeout=15)
                except Exception:
                    continue

                loc = res.headers.get("location", "")
                if not loc:
                    continue

                loc_host = urlparse(loc).netloc
                is_external = (
                    loc_host and loc_host != base_host
                    or loc.startswith("//")
                    or "javascript:" in loc.lower()
                    or "evil.com" in loc.lower()
                )
                if is_external:
                    self.scanner._add_finding({
                        "type": "Open Redirect", "subtype": "Unvalidated External Redirect",
                        "url": test_url, "parameter": param, "payload": payload,
                        "severity": "Medium", "confidence": 0.92,
                        "evidence": f"Location: {loc}",
                        "description": f"Parameter '{param}' redirects to arbitrary external URLs.",
                    })
                    return

                # Also check 200 responses that might contain a meta refresh redirect
                if res.status_code == 200:
                    if "evil.com" in res.text or "javascript:" in res.text.lower():
                        self.scanner._add_finding({
                            "type": "Open Redirect", "subtype": "Meta/JS Redirect",
                            "url": test_url, "parameter": param, "payload": payload,
                            "severity": "Medium", "confidence": 0.80,
                            "evidence": "Redirect target in response body",
                            "description": f"Parameter '{param}' may allow redirect via meta/JS.",
                        })
                        return

    # ── CORS Misconfiguration ─────────────────────────────────────────────────
    async def test_cors(self, client, url: str, param: str) -> None:
        """Test for CORS misconfiguration by sending requests with different origins."""
        evil_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            url,  # Same origin (should be allowed)
        ]

        for origin in evil_origins[:2]:
            try:
                res = await client.get(
                    url,
                    headers={"Origin": origin},
                    follow_redirects=True,
                    timeout=15,
                )
                if not res:
                    continue

                acao = res.headers.get("access-control-allow-origin", "")
                acac = res.headers.get("access-control-allow-credentials", "").lower()

                if acao == "*" and acac == "true":
                    self.scanner._add_finding({
                        "type": "CORS Misconfiguration", "subtype": "Wildcard+Credentials",
                        "url": url, "parameter": "CORS", "payload": f"Origin: {origin}",
                        "severity": "Critical", "confidence": 1.0,
                        "evidence": f"ACAO={acao} ACAC={acac}",
                        "description": "Any origin can make authenticated cross-origin requests.",
                    })
                    return

                if acao == origin and acac == "true" and "evil" in origin:
                    self.scanner._add_finding({
                        "type": "CORS Misconfiguration", "subtype": "Reflected Origin",
                        "url": url, "parameter": "CORS", "payload": f"Origin: {origin}",
                        "severity": "High", "confidence": 0.95,
                        "evidence": f"Reflected: ACAO={acao}",
                        "description": "Server mirrors Origin header — all origins allowed with credentials.",
                    })
                    return

                if acao == origin and "evil" in origin and acac != "true":
                    self.scanner._add_finding({
                        "type": "CORS Misconfiguration", "subtype": "Reflected Origin (No Creds)",
                        "url": url, "parameter": "CORS", "payload": f"Origin: {origin}",
                        "severity": "Medium", "confidence": 0.85,
                        "evidence": f"Reflected: ACAO={acao} (no credentials)",
                        "description": "Server mirrors Origin header — data readable cross-origin.",
                    })
                    return
            except Exception:
                continue

    # ── Form XSS ──────────────────────────────────────────────────────────────
    async def test_form_xss(self, client, form: dict) -> None:
        url    = form["url"]
        method = form["method"]
        base   = dict(form["inputs"])

        for payload in XSS_PAYLOADS[:12]:
            for mutated in _xss_mutations(payload)[:2]:
                data = {k: mutated for k in base}
                if method == "POST":
                    res = await self.scanner._req(client, "POST", url, data=data, timeout=15)
                else:
                    res = await self.scanner._req(client, "GET", url, params=data, timeout=15)
                if res and mutated in res.text:
                    self.scanner._add_finding({
                        "type": "Cross-Site Scripting (XSS)", "subtype": f"Reflected via Form ({method})",
                        "url": url, "parameter": "form", "payload": mutated,
                        "severity": "High", "confidence": 0.88,
                        "evidence": "Payload reflected after form submission",
                        "description": f"Form at {url} reflects unsanitised input.",
                    })
                    return
