# core/rate_limiter.py
# NOTE: This module-level rate limiter is used by api/main.py via
# scanner/rate_limiter.py RateLimiter class.
# This file (core/rate_limiter.py) is a legacy function-based version
# and is no longer imported anywhere — safe to delete.
# Keeping it here only to avoid import errors if something references it.

import time
from urllib.parse import urlparse

last_request = {}


def allow_request(url, delay=1):
    domain = urlparse(url).netloc
    now    = time.time()

    if domain in last_request and now - last_request[domain] < delay:
        return False

    last_request[domain] = now
    return True