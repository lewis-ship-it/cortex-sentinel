import requests
from urllib.parse import urljoin

class ActiveScanner:
    def __init__(self):
        # Payloads for SQL Injection
        self.sql_payloads = ["' OR '1'='1", "'; WAITFOR DELAY '0:0:5'--"]
        # Payloads for XSS (Cross-Site Scripting)
        self.xss_payloads = [
            "<script>alert('sentinel')</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert('sentinel')>"
        ]

    def scan_url(self, url):
        all_findings = []
        
        # Run SQL Injection Checks
        all_findings.extend(self._check_sql_injection(url))
        
        # Run XSS Checks
        all_findings.extend(self._check_xss(url))
        
        return all_findings

    def _check_xss(self, url):
        xss_findings = []
        for payload in self.xss_payloads:
            try:
                # We test by sending the payload in a common parameter like 'q' or 'search'
                test_url = f"{url}?q={payload}"
                response = requests.get(test_url, timeout=10)
                
                # VERIFICATION LOOP: Does the literal payload appear in the HTML?
                if payload in response.text:
                    xss_findings.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "payload": payload,
                        "severity": "Medium-High",
                        "description": "Unsanitized input reflected in HTML"
                    })
            except Exception:
                continue
        return xss_findings

    def _check_sql_injection(self, url):
        sql_findings = []
        for payload in self.sql_payloads:
            try:
                # We test by sending the payload in a common parameter like 'id' or 'user'
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=10)

                # VERIFICATION LOOP: Does the literal payload appear in the HTML?
                if payload in response.text:
                    sql_findings.append({
                        "type": "SQL Injection",
                        "payload": payload,
                        "severity": "Critical",
                        "description": "Unsanitized input reflected in SQL query"
                    })
            except Exception:
                continue
        return sql_findings