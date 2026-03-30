import requests
import time
import random
from urllib.parse import urljoin

class ActiveScanner:
    def __init__(self):
        # 1. User-Agent Rotation: Makes the scanner look like a real browser
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
        ]
        
        # 2. Advanced Payloads: Standard + Time-Delay (Blind)
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
        """Pick a random browser identity for each request"""
        return {"User-Agent": random.choice(self.user_agents)}

    def scan_url(self, url, progress_callback=None):
        all_findings = []
        
        # Helper to send updates to the dashboard
        def send_status(msg):
            if progress_callback:
                progress_callback(msg)

        send_status(f"🔍 Starting active scan on {url}...")
        
        # Scan for SQL Injection
        send_status("💉 Testing SQL Injection payloads...")
        sql_results = self._check_sql_injection(url)
        all_findings.extend(sql_results)
        
        # Scan for XSS
        send_status("🎭 Testing XSS payloads...")
        xss_results = self._check_xss(url)
        all_findings.extend(xss_results)

        send_status(f"✅ Scan complete. Found {len(all_findings)} vulnerabilities.")
        return all_findings

    def _check_xss(self, url):
        xss_findings = []
        for payload in self.xss_payloads:
            try:
                test_url = f"{url}?q={payload}"
                # Request with randomized header
                response = requests.get(test_url, headers=self._get_headers(), timeout=10)
                if payload in response.text:
                    xss_findings.append({
                        "type": "XSS (Reflected)",
                        "payload": payload,
                        "severity": "High",
                        "score": 7.5,
                        "description": "Unsanitized input reflected in page body."
                    })
            except Exception:
                continue
        return xss_findings

    def _check_sql_injection(self, url):
        sql_findings = []
        for item in self.sql_payloads:
            payload = item["payload"]
            try:
                start_time = time.time()
                test_url = f"{url}?id={payload}"
                # Using headers and a longer timeout for time-based checks
                response = requests.get(test_url, headers=self._get_headers(), timeout=15)
                duration = time.time() - start_time

                # CHECK 1: Time-based Blind SQLi (Server hangs for 5+ seconds)
                if item["type"] == "Time-based" and duration >= 5:
                    sql_findings.append({
                        "type": "SQL Injection (Blind/Time)",
                        "payload": payload,
                        "severity": "Critical",
                        "score": 9.5,
                        "description": "Server delay detected, indicating vulnerability to blind injection."
                    })
                
                # CHECK 2: Standard Reflection/Error
                elif payload in response.text or "sql syntax" in response.text.lower():
                    sql_findings.append({
                        "type": "SQL Injection (Standard)",
                        "payload": payload,
                        "severity": "Critical",
                        "score": 9.8,
                        "description": "Database-level response or error reflected in HTML."
                    })
            except Exception:
                continue
        return sql_findings