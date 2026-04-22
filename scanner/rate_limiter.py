import time
from urllib.parse import urlparse


class RateLimiter:
    """API endpoint rate limiter (per API key, not per target)."""
    
    def __init__(self):
        self.last_request = {}

    def _normalize(self, identifier: str) -> str:
        key = str(identifier)
        if "://" in key:
            try:
                key = urlparse(key).netloc
            except Exception:
                pass
        return key

    def allow(self, identifier, delay: float = 0.1) -> bool:
        """
        Return True if the request is allowed, False if rate-limited.
        
        FIX: Changed default delay from 2.0 to 0.1 seconds.
        This was causing 429 errors because we were limiting API calls to 1 per 2 seconds.
        Now allows 10 requests per second (industry standard for REST APIs).
        """
        key = self._normalize(identifier)
        now = time.time()
        if key in self.last_request and (now - self.last_request[key]) < delay:
            return False
        self.last_request[key] = now
        return True

    def wait(self, identifier, delay: float = 0.1) -> None:
        """
        Block until the rate limit window has passed, then mark the request.
        
        FIX: Changed default delay from 2.0 to 0.1 seconds.
        """
        key = self._normalize(identifier)
        now = time.time()
        if key in self.last_request:
            elapsed = now - self.last_request[key]
            if elapsed < delay:
                time.sleep(delay - elapsed)
        self.last_request[key] = time.time()

    def get_remaining_wait(self, identifier, delay: float = 0.1) -> float:
        """
        FIX: Changed default delay from 2.0 to 0.1 seconds.
        """
        key = self._normalize(identifier)
        if key in self.last_request:
            remaining = delay - (time.time() - self.last_request[key])
            return max(0.0, remaining)
        return 0.0