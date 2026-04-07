from urllib.parse import urlparse

class SafetyGuard:

    def __init__(self):
        self.blocked_keywords = [
            "bank",
            "paypal",
            "government",
            "login.microsoft",
            "facebook"
        ]

    def is_allowed(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        for keyword in self.blocked_keywords:
            if keyword in domain:
                return False

        return True