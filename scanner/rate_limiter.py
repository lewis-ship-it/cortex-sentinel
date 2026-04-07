import time
from urllib.parse import urlparse

class RateLimiter:
    def __init__(self):
        # Stores the last successful timestamp for a key (URL or User ID)
        self.last_request = {}

    def allow(self, identifier, delay=2):
        """
        Check if a request is allowed based on a time delay.
        Matches the .allow() call in api/main.py.
        """
        # 1. Normalize the identifier (if it's a URL, use the domain)
        key = str(identifier)
        if "://" in key:
            try:
                key = urlparse(key).netloc
            except Exception:
                pass # Fallback to full string if parse fails
        
        now = time.time()
        
        # 2. Check the "Cooldown" period
        if key in self.last_request:
            elapsed = now - self.last_request[key]
            if elapsed < delay:
                return False
        
        # 3. Update the timestamp and allow
        self.last_request[key] = now
        return True

    def get_remaining_wait(self, identifier, delay=2):
        """Optional helper to tell the user how long to wait."""
        key = str(identifier)
        if "://" in key:
            key = urlparse(key).netloc
            
        if key in self.last_request:
            remaining = delay - (time.time() - self.last_request[key])
            return max(0, remaining)
        return 0