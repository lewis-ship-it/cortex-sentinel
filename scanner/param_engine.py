# scanner/param_engine.py

from urllib.parse import urlparse, parse_qs

class ParamEngine:
    def extract_params(self, url):
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    def inject_payload(self, url, param, payload):
        if "?" not in url:
            return f"{url}?{param}={payload}"
        return f"{url}&{param}={payload}"