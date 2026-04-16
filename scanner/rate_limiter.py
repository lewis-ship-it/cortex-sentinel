import time
from urllib.parse import urlparse


class RateLimiter:
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

    def allow(self, identifier, delay: float = 2.0) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        key = self._normalize(identifier)
        now = time.time()
        if key in self.last_request and (now - self.last_request[key]) < delay:
            return False
        self.last_request[key] = now
        return True

    def wait(self, identifier, delay: float = 2.0) -> None:
        """Block until the rate limit window has passed, then mark the request."""
        key = self._normalize(identifier)
        now = time.time()
        if key in self.last_request:
            elapsed = now - self.last_request[key]
            if elapsed < delay:
                time.sleep(delay - elapsed)
        self.last_request[key] = time.time()

    def get_remaining_wait(self, identifier, delay: float = 2.0) -> float:
        key = self._normalize(identifier)
        if key in self.last_request:
            remaining = delay - (time.time() - self.last_request[key])
            return max(0.0, remaining)
        return 0.0
