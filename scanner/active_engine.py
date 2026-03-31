import asyncio
import httpx
import time
import logging

from scanner.crawler import Crawler
from scanner.param_engine import ParamEngine
from scanner.detector import Detector
from scanner.auth_handler import AuthHandler

logging.basicConfig(level=logging.INFO)

class ActiveScanner:
    def __init__(self):
        self.param_engine = ParamEngine()
        self.detector = Detector()
        self.auth = AuthHandler()

        # Vulnerability Payloads
        self.true_payload = "' OR 1=1--"
        self.false_payload = "' AND 1=2--"
        self.time_payload = "'; WAITFOR DELAY '0:0:5'--"

        self.xss_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ]

        self.common_params = ["id", "q", "search", "page", "cat"]

    async def scan(self, base_url, auth_config=None):
        findings = []

        # Maintain one session for the entire scan to preserve cookies
        async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
            
            # --- AUTHENTICATION PHASE ---
            if auth_config:
                logging.info(f"[AUTH] Attempting {auth_config.get('type')} authentication...")
                if auth_config.get("type") == "login":
                    await self.auth.login(
                        client, 
                        auth_config["login_url"], 
                        auth_config["username"], 
                        auth_config["password"]
                    )
                elif auth_config.get("type") == "cookie":
                    self.auth.inject_cookies(client, auth_config["cookies"])

            # --- CRAWLING PHASE ---
            crawler = Crawler(base_url)
            endpoints, forms = await crawler.crawl(client)
            logging.info(f"[CRAWL] Found {len(endpoints)} endpoints and {len(forms)} forms")

            # --- TESTING PHASE ---
            tasks = []
            for url in endpoints:
                params = self.param_engine.extract_params(url) or self.common_params
                for param in params:
                    tasks.append(self.test_sqli(client, url, param))
                    tasks.append(self.test_xss(client, url, param))

            for form in forms:
                tasks.append(self.test_form(client, form))

            # Gather all concurrent scan results
            results = await asyncio.gather(*tasks)

            # Flatten results and filter None
            for r in results:
                if r:
                    if isinstance(r, list):
                        findings.extend(r)
                    else:
                        findings.append(r)

        return findings

    async def test_sqli(self, client, url, param):
        try:
            baseline = await client.get(url)
            true_url = self.param_engine.inject_payload(url, param, self.true_payload)
            false_url = self.param_engine.inject_payload(url, param, self.false_payload)

            true_res = await client.get(true_url)
            false_res = await client.get(false_url)

            # Time-based check
            start = time.time()
            delay_url = self.param_engine.inject_payload(url, param, self.time_payload)
            await client.get(delay_url)
            duration = time.time() - start

            if self.detector.detect_sqli(baseline, true_res, false_res, {"delay": duration}):
                return {
                    "type": "SQL Injection",
                    "url": true_url,
                    "severity": "Critical",
                    "description": f"Boolean or Time-based SQLi detected on parameter: {param}"
                }
        except Exception as e:
            logging.error(f"SQLi Error on {url}: {e}")
        return None

    async def test_xss(self, client, url, param):
        results = []
        for payload in self.xss_payloads:
            try:
                test_url = self.param_engine.inject_payload(url, param, payload)
                res = await client.get(test_url)
                if self.detector.detect_xss(res.text, payload):
                    results.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "url": test_url,
                        "payload": payload,
                        "severity": "High"
                    })
            except Exception as e:
                logging.error(f"XSS Error on {url}: {e}")
        return results if results else None

    async def test_form(self, client, form):
        results = []
        for payload in self.xss_payloads:
            data = {i: payload for i in form["inputs"]}
            try:
                if form["method"] == "post":
                    res = await client.post(form["url"], data=data)
                else:
                    res = await client.get(form["url"], params=data)
                
                if self.detector.detect_xss(res.text, payload):
                    results.append({
                        "type": "Form-based XSS",
                        "url": form["url"],
                        "payload": payload,
                        "severity": "High"
                    })
            except Exception as e:
                logging.error(f"Form Error on {form['url']}: {e}")
        return results if results else None