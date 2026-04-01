# scanner/safety.py

import requests
import ssl
import socket
from urllib.parse import urlparse


class SafetyAuditor:
    def __init__(self, url):
        self.url = url
        parsed = urlparse(url)
        self.hostname = parsed.netloc

    # -----------------------
    # SECURITY HEADERS CHECK
    # -----------------------
    def audit_headers(self):
        required_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options"
        ]

        try:
            res = requests.get(self.url, timeout=5)

            report = {
                h: res.headers.get(h, "MISSING")
                for h in required_headers
            }

            return report

        except Exception as e:
            return {"error": str(e)}

    # -----------------------
    # SSL CHECK
    # -----------------------
    def check_ssl(self):
        try:
            context = ssl.create_default_context()

            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()

                    return {
                        "status": "Valid",
                        "issuer": cert.get('issuer'),
                        "subject": cert.get('subject')
                    }

        except Exception as e:
            return {
                "status": "Issue Detected",
                "details": str(e)
            }