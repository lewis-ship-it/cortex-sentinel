import asyncio
import httpx
import time
import logging

from scanner.crawler import Crawler
from scanner.param_engine import ParamEngine
from scanner.detector import Detector
from scanner.auth_handler import AuthHandler
from scanner.priority_engine import PriorityEngine
from scanner.learning_engine import LearningEngine
from scanner.ai_brain import AIBrain

logging.basicConfig(level=logging.INFO)


class ActiveScanner:
    def __init__(self):
        self.param_engine = ParamEngine()
        self.detector = Detector()
        self.auth = AuthHandler()
        self.priority = PriorityEngine()
        self.learning = LearningEngine()
        self.brain = AIBrain()

        # -------------------------
        # PAYLOAD ENGINE (SMART)
        # -------------------------
        self.payload_variants = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "' OR 'a'='a"
        ]

        self.xss_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ]

        self.common_params = ["id", "q", "search", "page", "cat"]

        # -------------------------
        # CONTROL LIMITS
        # -------------------------
        self.semaphore = asyncio.Semaphore(10)
        self.max_requests = 300
        self.request_count = 0

    # -------------------------
    # SAFE REQUEST
    # -------------------------
    async def safe_request(self, client, method, url, **kwargs):
        if self.request_count >= self.max_requests:
            return None

        self.request_count += 1

        try:
            if method == "GET":
                return await client.get(url, **kwargs)
            elif method == "POST":
                return await client.post(url, **kwargs)
        except Exception as e:
            logging.error(f"[REQUEST ERROR] {url} -> {e}")
            return None

    # -------------------------
    # MAIN SCAN
    # -------------------------
    async def scan(self, base_url, auth_config=None):
        findings = []
        tasks = []

        async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:

            # AUTH
            if auth_config:
                logging.info("[AUTH] Attempting authentication")

                if auth_config.get("type") == "login":
                    await self.auth.login(
                        client,
                        auth_config["login_url"],
                        auth_config["username"],
                        auth_config["password"]
                    )

                elif auth_config.get("type") == "cookie":
                    self.auth.inject_cookies(client, auth_config["cookies"])

            # CRAWL
            crawler = Crawler(base_url)
            endpoints, forms = await crawler.crawl(client)

            logging.info(f"[CRAWL] Found {len(endpoints)} endpoints")

            # -------------------------
            # SMART PRIORITIZATION (LEARNING BOOST)
            # -------------------------
            scored = []

            for ep in endpoints:
                base = self.priority.score_endpoint(ep)
                learned = self.learning.get_priority_boost(ep)
                scored.append((ep, base + learned))

            scored.sort(key=lambda x: x[1], reverse=True)
            prioritized_endpoints = await self.brain.prioritize_targets(list(endpoints))

            # -------------------------
            # TESTING
            # -------------------------
            for url in prioritized_endpoints:
                params = self.param_engine.extract_params(url) or self.common_params

                for param in params:
                    tasks.append(self.safe_task(self.test_sqli, client, url, param))
                    tasks.append(self.safe_task(self.test_xss, client, url, param))

            for form in forms:
                tasks.append(self.safe_task(self.test_form, client, form))

            results = await asyncio.gather(*tasks)

            # COLLECT
            for r in results:
                if r:
                    if isinstance(r, list):
                        findings.extend(r)
                    else:
                        findings.append(r)

        # -------------------------
        # LEARNING LOOP
        # -------------------------
        validated = []

        for f in findings:
            ai_result = await self.brain.validate_finding(f)

            if ai_result.get("valid"):
                f["confidence"] = ai_result.get("confidence", 0.7)
                f["ai_reason"] = ai_result.get("reason")
                f["severity"] = ai_result.get("severity", f.get("severity"))

                validated.append(f)
                self.learning.record_finding(f)

        findings = validated

        logging.info(f"[SCAN COMPLETE] Found {len(findings)} issues")
        return findings

    async def safe_task(self, func, *args):
        async with self.semaphore:
            return await func(*args)

    # -------------------------
    # SQLi (MULTI-PAYLOAD + VALIDATION)
    # -------------------------
    async def test_sqli(self, client, url, param):
        ai_payloads = await self.brain.generate_payloads({
            "url": url,
            "param": param
        })

        all_payloads = self.payload_variants + ai_payloads
        try:
            baseline = await self.safe_request(client, "GET", url)
            if not baseline:
                return None

            for payload in all_payloads:
                test_url = self.param_engine.inject_payload(url, param, payload)
                res = await self.safe_request(client, "GET", test_url)

                if not res:
                    continue

                # SIGNAL DETECTION
                if payload in res.text:

                    # DOUBLE VALIDATION
                    confirm = await self.safe_request(client, "GET", test_url)

                    if confirm and confirm.text == res.text:
                        return {
                            "type": "SQL Injection",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "Critical",
                            "confidence": 0.9,
                            "evidence": payload
                        }

        except Exception as e:
            logging.error(f"[SQLi ERROR] {url} -> {e}")

        return None

    # -------------------------
    # XSS (CONTEXT-AWARE)
    # -------------------------
    async def test_xss(self, client, url, param):
        results = []

        for payload in self.xss_payloads:
            try:
                test_url = self.param_engine.inject_payload(url, param, payload)
                res = await self.safe_request(client, "GET", test_url)

                if not res:
                    continue

                if payload in res.text:

                    if "<script>" in res.text or "onerror" in res.text:
                        severity = "Critical"
                    else:
                        severity = "High"

                    finding = {
                        "type": "Cross-Site Scripting (XSS)",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "severity": severity,
                        "confidence": 0.8,
                        "evidence": payload
                    }

                    results.append(finding)

            except Exception as e:
                logging.error(f"[XSS ERROR] {url} -> {e}")

        return results if results else None

    # -------------------------
    # FORM TESTING
    # -------------------------
    async def test_form(self, client, form):
        results = []

        for payload in self.xss_payloads:
            data = {i: payload for i in form["inputs"]}

            try:
                if form["method"].lower() == "post":
                    res = await self.safe_request(client, "POST", form["url"], data=data)
                else:
                    res = await self.safe_request(client, "GET", form["url"], params=data)

                if not res:
                    continue

                if payload in res.text:
                    results.append({
                        "type": "Form XSS",
                        "url": form["url"],
                        "payload": payload,
                        "severity": "High",
                        "confidence": 0.75,
                        "evidence": payload
                    })

            except Exception as e:
                logging.error(f"[FORM ERROR] {form['url']} -> {e}")

        return results if results else None
