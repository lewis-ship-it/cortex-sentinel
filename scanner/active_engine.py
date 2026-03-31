# scanner/active_engine.py
import asyncio
import httpx
import time
import logging

from scanner.crawler import Crawler
from scanner.param_engine import ParamEngine
from scanner.detector import Detector
from scanner.auth_handler import AuthHandler
from scanner.playwright_engine import PlaywrightScanner
from scanner.priority_engine import PriorityEngine
from scanner.cvss import CVSS

logging.basicConfig(level=logging.INFO)

class ActiveScanner:
    def __init__(self):
        self.param_engine = ParamEngine()
        self.detector = Detector()
        self.auth = AuthHandler() # Your added AuthHandler
        self.browser = PlaywrightScanner()  # Your added PlaywrightScanner

        self.true_payload = "' OR 1=1--"
        self.false_payload = "' AND 1=2--"
        self.time_payload = "'; WAITFOR DELAY '0:0:5'--"

        self.xss_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>"
        ]

        self.common_params = ["id", "q", "search"]
        self.priority = PriorityEngine()
        self.cvss = CVSS()

    async def scan(self, base_url, auth_config=None):
        findings = []

        # We use one client session for both Auth and Scanning to persist cookies/tokens
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            
            # -------------------------
            # AUTH HANDLING (Integrated)
            # -------------------------
            if auth_config:
                if auth_config.get("type") == "login":
                    success = await self.auth.login(
                        client,
                        auth_config["login_url"],
                        auth_config["username"],
                        auth_config["password"]
                    )
                    if not success:
                        logging.warning("[AUTH] Login failed. Proceeding unauthenticated")
                    else:
                        logging.info("[AUTH] Login successful")

                elif auth_config.get("type") == "cookie":
                    self.auth.inject_cookies(client, auth_config["cookies"])
                    logging.info("[AUTH] Cookies injected")

            # -------------------------
            # CRAWLING & TESTING
            # -------------------------
            crawler = Crawler(base_url)
            endpoints, forms = await crawler.crawl(client)
            # -----------------------
            # PLAYWRIGHT SCAN
            # -----------------------
            try:
                pw_findings, pw_endpoints = await self.browser.scan(
                    base_url, auth_config
                )

                logging.info(f"[PLAYWRIGHT] Found {len(pw_endpoints)} endpoints")

                endpoints.update(pw_endpoints)
                findings.extend(pw_findings)

            except Exception as e:
                logging.error(f"[PLAYWRIGHT ERROR] {e}")

            logging.info(f"[CRAWL] endpoints={len(endpoints)} forms={len(forms)}")

            tasks = []
            endpoints = self.priority.prioritize(endpoints)

            logging.info(f"[PRIORITY] Top targets: {endpoints[:5]}")
            for url in endpoints:
                params = self.param_engine.extract_params(url)
                if not params:
                    params = self.common_params

                for param in params:
                    tasks.append(self.test_sqli(client, url, param))
                    tasks.append(self.test_xss(client, url, param))

            for form in forms:
                tasks.append(self.test_form(client, form))

            results = await asyncio.gather(*tasks)

            for r in results:
                if r:
                    findings.extend(r if isinstance(r, list) else [r])

        return findings

    # --- KEEPING ALL YOUR TEST METHODS BELOW ---
    async def test_sqli(self, client, url, param):
        try:
            baseline = await client.get(url)
            true_url = self.param_engine.inject_payload(url, param, self.true_payload)
            false_url = self.param_engine.inject_payload(url, param, self.false_payload)

            true_res = await client.get(true_url)
            false_res = await client.get(false_url)

            start = time.time()
            delay_url = self.param_engine.inject_payload(url, param, self.time_payload)
            await client.get(delay_url)
            delay = time.time() - start

            if self.detector.detect_sqli(baseline, true_res, false_res, {"delay": delay}):
                logging.warning(f"[SQLi VERIFIED] {true_url}")
                score = self.cvss.calculate("SQL Injection")
                return {
                    "type": "SQL Injection",
                    "url": true_url,
                    "cvss": score,
                    "severity": self.cvss.severity_label(score)
        }
                
        except Exception as e:
            logging.error(f"[SQLi ERROR] {e}")
        return None

    async def test_xss(self, client, url, param):
        findings = []
        for payload in self.xss_payloads:
            try:
                test_url = self.param_engine.inject_payload(url, param, payload)
                res = await client.get(test_url)
                if self.detector.detect_xss(res.text, payload):
                    logging.warning(f"[XSS VERIFIED] {test_url}")
                    findings.append({"type": "XSS", "url": test_url, "payload": payload, "severity": "High"})
            except Exception as e:
                logging.error(f"[XSS ERROR] {e}")
        return findings if findings else None

    async def test_form(self, client, form):
        findings = []
        for payload in self.xss_payloads:
            data = {i: payload for i in form["inputs"]}
            try:
                if form["method"] == "post":
                    res = await client.post(form["url"], data=data)
                else:
                    res = await client.get(form["url"], params=data)
                if self.detector.detect_xss(res.text, payload):
                    logging.warning(f"[FORM XSS VERIFIED] {form['url']}")
                    findings.append({"type": "XSS", "url": form["url"], "payload": payload, "severity": "High"})
            except Exception as e:
                logging.error(f"[FORM ERROR] {e}")
        return findings if findings else None