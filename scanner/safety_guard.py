
# scanner/safety_guard.py
from urllib.parse import urlparse

class SafetyGuard:

    def __init__(self):
        # Using a set for O(1) lookup speed and exact matching
        self.BLOCKED_DOMAINS = {
            "paypal.com", 
            "login.microsoft.com", 
            "facebook.com",
            "google.com", 
            "apple.com", 
            "amazon.com",
            "chase.com",
            "bankofamerica.com"
        }

    def is_allowed(self, url):
        """
        Verifies if a URL is safe to scan.
        Prevents accidental scanning of major platforms or financial institutions.
        """
        try:
            parsed = urlparse(url)
            # Extract domain and normalize
            domain = parsed.netloc.lower()
            
            # Remove 'www.' prefix if present for consistent matching
            if domain.startswith("www."):
                domain = domain[4:]

            # Exact match check
            if domain in self.BLOCKED_DOMAINS:
                return False

            return True
        except Exception:
            # If URL is malformed, block it by default
            return False

