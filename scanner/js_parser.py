
# scanner/js_parser.py
# ──────────────────────────────────────────────────────────────────────────────
# JS PARSER — Extracts API endpoints, auth tokens, secrets, and hidden params
# from JavaScript source files and inline <script> blocks.
# ──────────────────────────────────────────────────────────────────────────────

import re
from urllib.parse import urljoin


class JSParser:
    """
    Parses JavaScript source to extract:
    - API endpoint paths (REST, GraphQL, fetch, axios, XHR)
    - Hardcoded secrets / API keys / tokens
    - Hidden parameters used in JS fetch calls
    - WebSocket endpoints
    """

    # Patterns for endpoint discovery
    ENDPOINT_PATTERNS = [
        r'["\'](/api/[^\s"\'<>?#]{2,80})["\']',
        r'["\'](/v\d+/[^\s"\'<>?#]{2,80})["\']',
        r'["\'](/graphql[^\s"\'<>?#]{0,40})["\']',
        r'["\'](/rest/[^\s"\'<>?#]{2,80})["\']',
        r'["\'](/admin[^\s"\'<>?#]{0,60})["\']',
        r'["\'](/internal[^\s"\'<>?#]{0,60})["\']',
        r'["\'](/debug[^\s"\'<>?#]{0,40})["\']',
        r'["\'](/health[^\s"\'<>?#]{0,40})["\']',
        r'["\'](/metrics[^\s"\'<>?#]{0,40})["\']',
        r'fetch\(\s*["\']([^\s"\'<>]{4,120})["\']',
        r'axios\.\w+\(\s*["\']([^\s"\'<>]{4,120})["\']',
        r'\.get\(\s*["\']([^\s"\'<>]{4,120})["\']',
        r'\.post\(\s*["\']([^\s"\'<>]{4,120})["\']',
        r'\.put\(\s*["\']([^\s"\'<>]{4,120})["\']',
        r'\.delete\(\s*["\']([^\s"\'<>]{4,120})["\']',
        r'url:\s*["\']([^\s"\'<>]{4,120})["\']',
        r'href:\s*["\']([^\s"\'<>]{4,120})["\']',
        r'action:\s*["\']([^\s"\'<>]{4,120})["\']',
        r'new\s+WebSocket\(\s*["\']([^\s"\'<>]{4,120})["\']',
        r'endpoint["\'\s:=]+["\']([^\s"\'<>]{4,120})["\']',
        r'baseURL["\'\s:=]+["\']([^\s"\'<>]{4,120})["\']',
        r'BASE_URL["\'\s:=]+["\']([^\s"\'<>]{4,120})["\']',
        r'API_URL["\'\s:=]+["\']([^\s"\'<>]{4,120})["\']',
    ]

    # Patterns for secrets / sensitive data in JS
    SECRET_PATTERNS = [
        (r'api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']',   "API Key"),
        (r'apiKey\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']',          "API Key"),
        (r'secret[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']', "Secret Key"),
        (r'access[_-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']', "Access Token"),
        (r'auth[_-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']',   "Auth Token"),
        (r'password\s*[:=]\s*["\']([^\s"\']{6,})["\']',                   "Hardcoded Password"),
        (r'client[_-]?secret\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',  "Client Secret"),
        (r'AKIA[0-9A-Z]{16}',                                              "AWS Access Key ID"),
        (r'eyJ[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=]{20,}', "JWT Token"),
        (r'sk-[A-Za-z0-9]{32,}',                                           "OpenAI-style API Key"),
        (r'ghp_[A-Za-z0-9]{36}',                                           "GitHub PAT"),
        (r'xox[bpoa]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}',               "Slack Token"),
        (r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',                  "SendGrid Key"),
        (r'AIza[0-9A-Za-z\-_]{35}',                                        "Google API Key"),
    ]

    # Hidden parameter patterns (params used in JS but not in HTML forms)
    PARAM_PATTERNS = [
        r'params\[[\'"]([\w\-]{1,40})[\'"]\]',
        r'data\[[\'"]([\w\-]{1,40})[\'"]\]',
        r'body\[[\'"]([\w\-]{1,40})[\'"]\]',
        r'["\']([\w\-]{1,40})["\']\s*:\s*\w+\s*[,}]',  # JSON object keys
        r'formData\.append\(["\'](\w+)["\']',
        r'searchParams\.(?:set|append)\(["\'](\w+)["\']',
        r'getParameter\(["\'](\w+)["\']',
    ]

    def extract_endpoints(self, js_text: str, base_url: str = "") -> set:
        """
        Parse JS source text and return a set of discovered endpoint URLs.
        """
        found = set()
        for pattern in self.ENDPOINT_PATTERNS:
            try:
                matches = re.findall(pattern, js_text, re.IGNORECASE)
                for match in matches:
                    if match.startswith("/"):
                        if base_url:
                            found.add(urljoin(base_url, match))
                        else:
                            found.add(match)
                    elif match.startswith("http://") or match.startswith("https://"):
                        found.add(match)
                    elif match.startswith("ws://") or match.startswith("wss://"):
                        found.add(match)
                    elif base_url and not match.startswith(("data:", "javascript:", "#")):
                        found.add(urljoin(base_url, match))
            except re.error:
                continue
        return found

    def extract_secrets(self, js_text: str) -> list:
        """
        Scan JS source for hardcoded secrets, API keys, and tokens.
        Returns a list of dicts: [{label, value, severity}]
        """
        findings = []
        for pattern, label in self.SECRET_PATTERNS:
            try:
                matches = re.findall(pattern, js_text, re.IGNORECASE)
                for match in matches:
                    # Skip obvious placeholders
                    if match.lower() in ("your_api_key", "xxx", "placeholder", "example", "changeme", "todo"):
                        continue
                    findings.append({
                        "label":    label,
                        "value":    match[:60] + ("…" if len(match) > 60 else ""),
                        "severity": "High",
                    })
            except re.error:
                continue
        return findings

    def extract_hidden_params(self, js_text: str) -> set:
        """
        Find parameter names used in JS that don't appear in HTML forms.
        These are prime targets for injection testing.
        """
        params = set()
        for pattern in self.PARAM_PATTERNS:
            try:
                matches = re.findall(pattern, js_text, re.IGNORECASE)
                for m in matches:
                    if 2 < len(m) < 40 and m.isidentifier():
                        params.add(m)
            except re.error:
                continue
        return params

