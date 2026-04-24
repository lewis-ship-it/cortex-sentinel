# scanner/dast/param_engine.py
# AGGRESSIVE PARAMETER ENGINE — Extracts, discovers, and injects into parameters
# Includes hidden parameter brute-forcing, path parameter fuzzing, and header injection

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

# Parameters commonly found in web applications (expanded for JuiceShop coverage)
INTERESTING_PARAMS = [
    # Object references
    "id","user","uid","userid","user_id","account","item","product",
    "order","order_id","invoice","invoice_id","doc","doc_id",
    # Search/query
    "q","query","search","keyword","term","s","k","find","filter",
    # Pagination
    "page","p","pg","offset","limit","start","num","count","size","per_page",
    # File/path
    "file","path","dir","folder","document","doc","name","include","require",
    # URL/redirect
    "url","link","redirect","next","return","dest","goto","redir","route",
    "callback","jsonp","forward","to","out","exit","away",
    # Auth/session
    "token","key","api_key","auth","session","sid","csrf","_csrf","xsrf",
    "access_token","refresh_token","jwt","bearer",
    # Sort/filter
    "order","sort","by","filter","orderby","sortby","direction","asc","desc",
    # User data
    "email","username","phone","password","pass","passwd","pwd",
    "name","first_name","last_name","nickname","display_name",
    # Content
    "comment","message","text","content","body","description","title",
    "subject","note","feedback","review","rating",
    # Referrer/source
    "ref","referrer","source","from","origin","referer",
    # Format/output
    "callback","jsonp","format","output","type","view","mode","action",
    "tab","section","category","cat","tag",
    # Language/locale
    "lang","language","locale","region","country",
    # Debug/dev
    "debug","test","preview","draft","dev","trace","verbose","log",
    # JuiceShop-specific
    "BasketId","ProductId","quantity","coupon","couponCode",
    "searchTerms","searchQuery","queryTerm",
    "UserId","email","password","newPassword","repeatPassword",
    "securityQuestion","securityAnswer",
    "address","city","state","country","zipcode",
    "number","expiryMonth","expiryYear","ccv",
    "comment","rating","message",
    "ip","domain","host","port",
]
SAFE_PARAMETERS = ["lang", "theme"]

# Hidden parameters to brute-force on every endpoint
HIDDEN_PARAMS = [
    "admin", "debug", "test", "dev", "internal", "secret",
    "api_key", "apikey", "key", "token", "access_token",
    "callback", "jsonp", "format", "output",
    "id", "user_id", "uid", "account_id",
    "file", "path", "dir", "include", "template",
    "redirect", "url", "next", "return", "goto",
    "q", "query", "search", "s",
    "page", "p", "offset", "limit",
    "sort", "order", "filter",
    "role", "is_admin", "admin", "privilege",
    "username", "email", "password",
    "comment", "message", "text",
    "lang", "locale",
]


class ParamEngine:
    def __init__(self):
        self.payloads = {
            "sqli": ["'", "\"", "' OR 1=1--", "admin'--", "' UNION SELECT 1,2,3--"],
            "xss": ["<script>alert(1)</script>", "\"><script>alert(1)</script>"],
            "traversal": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
            "open_redirect": ["//evil.com", "https://evil.com"],
            "ssti": ["{{7*7}}", "${7*7}"],
            "cmdi": ["; id", "| id"],
        }

    def extract_params(self, url: str) -> list:
        """Extract existing query parameters from a URL."""
        return list(parse_qs(urlparse(url).query).keys())

    def inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject a payload into a specific parameter in the URL."""
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[param] = [payload]
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(query, doseq=True), parsed.fragment
        ))

    def add_param(self, url: str, param: str, value: str = "1") -> str:
        """Add a new parameter to the URL (for hidden param discovery)."""
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[param] = [value]
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(query, doseq=True), parsed.fragment
        ))

    def get_categorized_payloads(self, param: str) -> list:
        """Decide if a parameter gets a full attack or just a benign test."""
        if param in SAFE_PARAMETERS:
            return ["benign_test"]
        return [v for sublist in self.payloads.values() for v in sublist]

    def add_param_variants(self, url: str) -> list:
        """Returns URL variants with payloads injected into parameters."""
        variants = []
        params = self.extract_params(url)

        for param in params:
            payloads = self.get_categorized_payloads(param)
            for p in payloads:
                variants.append(self.inject_payload(url, param, p))
        return variants

    def get_hidden_param_urls(self, url: str) -> list:
        """Generate URLs with hidden parameters brute-forced onto them."""
        existing = set(self.extract_params(url))
        urls = []
        for param in HIDDEN_PARAMS:
            if param not in existing:
                urls.append(self.add_param(url, param, "1"))
        return urls

    def get_path_variants(self, url: str) -> list:
        """Generate path-based injection variants (e.g., /api/users/1 -> /api/users/{payload})."""
        parsed = urlparse(url)
        path = parsed.path
        variants = []

        # Find numeric segments in the path
        segments = path.split("/")
        for i, seg in enumerate(segments):
            if seg.isdigit():
                # Replace numeric ID with injection payloads
                for payload in ["1", "0", "-1", "999", "' OR 1=1--", "admin"]:
                    new_segments = segments[:]
                    new_segments[i] = quote(payload, safe='')
                    new_path = "/".join(new_segments)
                    variants.append(urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    )))
        return variants

    def get_header_injection_params(self) -> list:
        """Return parameters that should also be tested via HTTP headers."""
        return [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("X-Forwarded-Host", "localhost"),
            ("X-Host", "localhost"),
            ("X-Forwarded-Server", "localhost"),
            ("X-HTTP-Method-Override", "PUT"),
            ("X-Method-Override", "DELETE"),
            ("X-Override-Method", "PATCH"),
            ("Forwarded", "for=127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("True-Client-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Remote-Addr", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
        ]
