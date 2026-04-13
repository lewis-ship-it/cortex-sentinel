# scanner/dast/rate_limiter.py
import time
from urllib.parse import urlparse

class RateLimiter:
    def __init__(self):
        self.last_request = {}

    def _key(self, identifier: str) -> str:
        k = str(identifier)
        if "://" in k:
            try: k = urlparse(k).netloc
            except: pass
        return k

    def allow(self, identifier, delay: float = 0.5) -> bool:
        key = self._key(identifier)
        now = time.time()
        if key in self.last_request and (now - self.last_request[key]) < delay:
            return False
        self.last_request[key] = now
        return True

    def wait(self, identifier, delay: float = 0.5) -> None:
        key = self._key(identifier)
        now = time.time()
        if key in self.last_request:
            elapsed = now - self.last_request[key]
            if elapsed < delay:
                time.sleep(delay - elapsed)
        self.last_request[key] = time.time()
