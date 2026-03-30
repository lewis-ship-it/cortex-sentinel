import requests
import ssl
import socket

class SafetyAuditor:
    def __init__(self, url):
        self.url = url
        self.hostname = urlparse(url).netloc

    def audit_headers(self):
        # Security Checks: Security Headers [cite: 9]
        required_headers = [
            "Content-Security-Policy", 
            "Strict-Transport-Security", 
            "X-Frame-Options"
        ]
        try:
            res = requests.get(self.url, timeout=5)
            report = {h: res.headers.get(h, "MISSING") for h in required_headers}
            return report
        except Exception as e:
            return {"error": str(e)}

    def check_ssl(self):
        # Security Checks: SSL/TLS Issues [cite: 9]
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {"status": "Valid", "issuer": cert.get('issuer')}
        except Exception as e:
            return {"status": "Issue Detected", "details": str(e)}