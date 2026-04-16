# scanner/dast/modules/client_side.py
#
# FIXES:
#   - Open redirect: detects ANY external domain (not just google/bing)
#   - XSS: uses context-aware payloads from context_engine
#   - Added form XSS test method

import asyncio
import logging
from urllib.parse import urlparse
from scanner.dast.payloads import XSS_PAYLOADS, OPEN_REDIRECT_PAYLOADS

logger = logging.getLogger(__name__)

REDIRECT_PARAMS = frozenset({
    "redirect", "next", "return", "dest", "destination", "url", "goto",
    "redir", "return_url", "callback", "target", "link", "forward",
    "location", "continue", "ref", "return_to", "redirect_uri", "redirect_url",
})


class ClientSideModule:
    def __init__(self, scanner):
        self.scanner = scanner

    async def run(self, client, url: str, params: list) -> None:
        tasks = []
        for param in params:
            tasks.append(self.test_xss(client, url, param))
            tasks.append(self.test_open_redirect(client, url, param))
        await asyncio.gather(*tasks, return_exceptions=True)

    # ── XSS ───────────────────────────────────────────────────────────────────
    async def test_xss(self, client, url: str, param: str) -> None:
        # Phase 1: detect context with neutral canary
        context = await self.scanner._get_context(client, url, param)
        payloads = self.scanner.context_engine.get_payloads(context)
        if not payloads:
            payloads = XSS_PAYLOADS

        # Phase 2: verify reflection with canary
        canary = f"ctx_{param}"
        c_url  = self.scanner.param_engine.inject_payload(url, param, canary)
        c_res  = await self.scanner._req(client, "GET", c_url)
        if not c_res or canary not in c_res.text:
            return  # no reflection — skip

        # Phase 3: attack with targeted payloads
        for payload in payloads:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            res = await self.scanner._req(client, "GET", test_url)
            if res and payload in res.text:
                self.scanner._add_finding({
                    "type": "Cross-Site Scripting (XSS)", "subtype": f"Reflected ({context})",
                    "url": test_url, "parameter": param, "payload": payload,
                    "severity": "High" if context == "html" else "Critical",
                    "confidence": 0.90,
                    "evidence": f"Payload reflected verbatim in '{context}' context",
                    "description": f"Parameter '{param}' reflects unsanitised input in {context} context.",
                })
                return

    # ── Open Redirect ─────────────────────────────────────────────────────────
    async def test_open_redirect(self, client, url: str, param: str) -> None:
        if param.lower() not in REDIRECT_PARAMS:
            return

        base_host = urlparse(url).netloc

        for payload in OPEN_REDIRECT_PAYLOADS:
            test_url = self.scanner.param_engine.inject_payload(url, param, payload)
            try:
                # FIX: don't follow redirects — inspect Location header directly
                res = await client.get(test_url, follow_redirects=False, timeout=8)
            except Exception:
                continue

            loc = res.headers.get("location", "")
            if not loc:
                continue

            # FIX: check for ANY external domain, not just google/bing
            loc_host = urlparse(loc).netloc
            is_external = (
                loc_host and loc_host != base_host
                or loc.startswith("//")
                or "javascript:" in loc.lower()
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

    # ── Form XSS ──────────────────────────────────────────────────────────────
    async def test_form_xss(self, client, form: dict) -> None:
        url    = form["url"]
        method = form["method"]
        base   = dict(form["inputs"])

        for payload in XSS_PAYLOADS[:8]:
            data = {k: payload for k in base}
            if method == "POST":
                res = await self.scanner._req(client, "POST", url, data=data, timeout=12)
            else:
                res = await self.scanner._req(client, "GET", url, params=data, timeout=12)
            if res and payload in res.text:
                self.scanner._add_finding({
                    "type": "Cross-Site Scripting (XSS)", "subtype": f"Reflected via Form ({method})",
                    "url": url, "parameter": "form", "payload": payload,
                    "severity": "High", "confidence": 0.88,
                    "evidence": "Payload reflected after form submission",
                    "description": f"Form at {url} reflects unsanitised input.",
                })
                return
