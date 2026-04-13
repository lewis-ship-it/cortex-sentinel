# scanner/dast/param_engine.py
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

INTERESTING_PARAMS = [
    "id","user","uid","userid","user_id","account","item","product",
    "q","query","search","keyword","term","s","k",
    "page","p","pg","offset","limit","start","num",
    "file","path","dir","folder","document","doc","name",
    "url","link","redirect","next","return","dest","goto","redir",
    "cat","category","type","action","view","mode","tab",
    "lang","language","locale","region",
    "token","key","api_key","auth","session","sid",
    "order","sort","by","filter","orderby","sortby",
    "email","username","phone",
    "ref","referrer","source","from","origin",
    "callback","jsonp","format","output",
    "debug","test","preview","draft",
]

class ParamEngine:
    def extract_params(self, url: str) -> list:
        return list(parse_qs(urlparse(url).query).keys())

    def inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query  = parse_qs(parsed.query, keep_blank_values=True)
        query[param] = [payload]
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(query, doseq=True), parsed.fragment
        ))

    def add_param_variants(self, url: str) -> list:
        """Return URL variants with common params added if none exist."""
        if "?" in url:
            return [url]
        # Try adding common params to param-less URLs
        variants = []
        for param in INTERESTING_PARAMS[:10]:
            variants.append(f"{url}?{param}=1")
        return variants
