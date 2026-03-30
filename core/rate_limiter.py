import time
from urllib.parse import urlparse

last_request = {}

def allow_request(url, delay=1):
    domain = urlparse(url).netloc
    now = time.time()

    if domain in last_request and now - last_request[domain] < delay:
        return False

    last_request[domain] = now
    return True