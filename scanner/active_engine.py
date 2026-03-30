import asyncio
import httpx
import time

from scanner.crawler import Crawler
from scanner.param_engine import ParamEngine
from scanner.detector import Detector
from core.rate_limiter import allow_request

class ActiveScanner:
    def __init__(self):
        self.param_engine = ParamEngine()
        self.detector = Detector()

        self.sql_payloads = [
            ("' OR '1'='1", "error"),
            ("'; WAITFOR DELAY '0:0:5'--", "time")
        ]

        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ]

    async def scan(self, base_url):
        findings = []

        async with httpx.AsyncClient(timeout=10) as client:
            crawler = Crawler(base_url)
            endpoints, forms = await crawler.crawl(client)

            tasks = []

            for url in endpoints:
                params = self.param_engine.extract_params(url)

                for param in params:
                    for payload, mode in self.sql_payloads:
                        tasks.append(self.test_sqli(client, url, param, payload, mode))

                    for payload in self.xss_payloads:
                        tasks.append(self.test_xss(client, url, param, payload))

            for form in forms:
                tasks.append(self.test_form(client, form))

            results = await asyncio.gather(*tasks)

            findings = [r for r in results if r]

        return findings

    async def test_sqli(self, client, url, param, payload, mode):
        if not allow_request(url):
            return None

        try:
            baseline = await client.get(url)
            start = time.time()

            test_url = self.param_engine.inject_payload(url, param, payload)
            res = await client.get(test_url)

            duration = time.time() - start

            if self.detector.detect_sqli(res.text, baseline.text, duration, mode):
                return {
                    "type": "SQL Injection",
                    "url": test_url,
                    "payload": payload,
                    "severity": "Critical"
                }
        except:
            return None

    async def test_xss(self, client, url, param, payload):
        if not allow_request(url):
            return None

        try:
            test_url = self.param_engine.inject_payload(url, param, payload)
            res = await client.get(test_url)

            if self.detector.detect_xss(res.text, payload):
                return {
                    "type": "XSS",
                    "url": test_url,
                    "payload": payload,
                    "severity": "High"
                }
        except:
            return None

    async def test_form(self, client, form):
        try:
            data = {i: "test" for i in form["inputs"]}

            if form["method"] == "post":
                res = await client.post(form["url"], data=data)
            else:
                res = await client.get(form["url"], params=data)

            if "error" in res.text.lower():
                return {
                    "type": "Form Issue",
                    "url": form["url"],
                    "severity": "Medium"
                }
        except:
            return None