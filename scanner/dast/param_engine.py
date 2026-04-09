from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class ParamEngine:

    def extract_params(self, url):
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    def inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        query[param] = [payload]

        new_query = urlencode(query, doseq=True)

        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))