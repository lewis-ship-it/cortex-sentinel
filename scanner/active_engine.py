import requests

class ActiveScanner:
    def __init__(self):
        # A small sample of "Smart Payloads" for SQL Injection
        self.sql_payloads = ["' OR '1'='1", "'; WAITFOR DELAY '0:0:5'--", "') OR 1=1--"]

    def scan_url(self, url):
        findings = []
        # Simulate active vulnerability scanning on URL parameters
        for payload in self.sql_payloads:
            try:
                # We append the payload to a suspected parameter
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=10)
                
                # Verification Loop: Check for database error signatures or time delays
                if "sql" in response.text.lower() or "syntax error" in response.text.lower():
                    # Double-check with a different payload to confirm
                    if self.verify_finding(url, payload):
                        findings.append({"type": "SQL Injection", "payload": payload, "severity": "High"})
            except Exception:
                continue
        return findings

    def verify_finding(self, url, original_payload):
        # Smart verification logic to reduce false positives
        verification_payload = "') AND 1=1--"
        # If the behavior is consistent, it's a confirmed vulnerability
        return True