import requests
import time
import random
from urllib.parse import urljoin

class ActiveScanner:
    def __init__(self):
        # 1. User-Agent Rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
        ]
        
        # 2. Advanced Payloads
        self.sql_payloads = [
            {"payload": "' OR '1'='1", "type": "Boolean"},
            {"payload": "'; WAITFOR DELAY '0:0:5'--", "type": "Time-based"}, 
            {"payload": "'; SELECT SLEEP(5);--", "type": "Time-based"}
        ]
        self.xss_payloads = [
            "<script>alert('sentinel')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('sentinel')"
        ]

    def _get_headers(self):
        return {"User-Agent": random.choice(self.user_agents)}

    def scan_url(self, url, progress_callback=None):
        all_findings = []
        
        def log(msg):
            if progress_callback:
                progress_callback(msg)

        log(f"🔍 Starting active scan on {url}...")
        
        # SQL Injection
        log("💉 Testing SQL Injection payloads...")
        sql_results = self._check_sql_injection(url, log)
        all_findings.extend(sql_results)
        
        # XSS
        log("🎭 Testing XSS payloads...")
        xss_results = self._check_xss(url, log)
        all_findings.extend(xss_results)

        log(f"✅ Scan complete. Found {len(all_findings)} vulnerabilities.")
        return all_findings

    def _check_xss(self, url, log):
        xss_findings = []
        for payload in self.xss_payloads:
            try:
                log(f"   Testing XSS: {payload[:30]}...")
                test_url = f"{url}?q={payload}"
                response = requests.get(test_url, headers=self._get_headers(), timeout=10)
                if payload in response.text:
                    xss_findings.append({
                        "type": "XSS (Reflected)",
                        "payload": payload,
                        "severity": "High",
                        "score": 7.5,
                        "description": "Unsanitized input reflected in page body."
                    })
            except Exception as e:
                log(f"   ⚠️ XSS Error: {str(e)}")
        return xss_findings

    def _check_sql_injection(self, url, log):
        sql_findings = []
        for item in self.sql_payloads:
            payload = item["payload"]
            try:
                log(f"   Testing SQLi: {payload[:30]}...")
                start_time = time.time()
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, headers=self._get_headers(), timeout=15)
                duration = time.time() - start_time

                if item["type"] == "Time-based" and duration >= 5:
                    sql_findings.append({
                        "type": "SQL Injection (Blind/Time)",
                        "payload": payload,
                        "severity": "Critical",
                        "score": 9.5,
                        "description": "Server delay detected (Blind SQLi)."
                    })
                elif payload in response.text or "sql syntax" in response.text.lower():
                    sql_findings.append({
                        "type": "SQL Injection (Standard)",
                        "payload": payload,
                        "severity": "Critical",
                        "score": 9.8,
                        "description": "Database-level response reflected in HTML."
                    })
            except Exception as e:
                log(f"   ⚠️ SQLi Error: {str(e)}")
        return sql_findings