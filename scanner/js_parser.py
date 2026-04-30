# scanner/js_parser.py
# ──────────────────────────────────────────────────────────────────────────────
# JS PARSER — Extracts API endpoints, auth tokens, secrets, and hidden params
# from JavaScript source files and inline <script> blocks.
# ──────────────────────────────────────────────────────────────────────────────

import re
from urllib.parse import urljoin, urlparse
from typing import Set, List, Dict, Any, Optional, Pattern, Tuple
from dataclasses import dataclass
from enum import Enum


class SeverityLevel(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class SecretFinding:
    """Data class for secret findings."""
    label: str
    value: str
    severity: SeverityLevel
    context: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class ParserConfig:
    """Configuration for JS parsing."""
    max_secret_length: int = 60
    min_param_length: int = 2
    max_param_length: int = 40
    include_placeholders: bool = False
    validate_urls: bool = True


class JSParser:
    """
    Parses JavaScript source to extract:
    - API endpoint paths (REST, GraphQL, fetch, axios, XHR)
    - Hardcoded secrets / API keys / tokens
    - Hidden parameters used in JS fetch calls
    - WebSocket endpoints
    """

    # Patterns for endpoint discovery (compiled for performance)
    ENDPOINT_PATTERNS: List[Pattern] = [
        re.compile(pattern, re.IGNORECASE) for pattern in [
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
    ]

    # Patterns for secrets / sensitive data in JS (pre-compiled)
    SECRET_PATTERNS: List[Tuple[Pattern, str, SeverityLevel]] = [
        (re.compile(pattern, re.IGNORECASE), label, severity) for pattern, label, severity in [
            (r'api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']', "API Key", SeverityLevel.HIGH),
            (r'apiKey\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']', "API Key", SeverityLevel.HIGH),
            (r'secret[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']', "Secret Key", SeverityLevel.CRITICAL),
            (r'access[_-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']', "Access Token", SeverityLevel.HIGH),
            (r'auth[_-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']', "Auth Token", SeverityLevel.HIGH),
            (r'password\s*[:=]\s*["\']([^\s"\']{6,})["\']', "Hardcoded Password", SeverityLevel.CRITICAL),
            (r'client[_-]?secret\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Client Secret", SeverityLevel.CRITICAL),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", SeverityLevel.CRITICAL),
            (r'eyJ[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=]{20,}', "JWT Token", SeverityLevel.HIGH),
            (r'sk-[A-Za-z0-9]{32,}', "OpenAI-style API Key", SeverityLevel.HIGH),
            (r'ghp_[A-Za-z0-9]{36}', "GitHub PAT", SeverityLevel.HIGH),
            (r'xox[bpoa]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}', "Slack Token", SeverityLevel.HIGH),
            (r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', "SendGrid Key", SeverityLevel.HIGH),
            (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", SeverityLevel.HIGH),
            (r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', "Private Key", SeverityLevel.CRITICAL),
            (r'session[_-]?secret\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Session Secret", SeverityLevel.CRITICAL),
        ]
    ]

    # Hidden parameter patterns (compiled)
    PARAM_PATTERNS: List[Pattern] = [
        re.compile(pattern, re.IGNORECASE) for pattern in [
            r'params\[[\'"]([\w\-]{1,40})[\'"]\]',
            r'data\[[\'"]([\w\-]{1,40})[\'"]\]',
            r'body\[[\'"]([\w\-]{1,40})[\'"]\]',
            r'["\']([\w\-]{1,40})["\']\s*:\s*\w+\s*[,}]',  # JSON object keys
            r'formData\.append\(["\'](\w+)["\']',
            r'searchParams\.(?:set|append)\(["\'](\w+)["\']',
            r'getParameter\(["\'](\w+)["\']',
            r'\.get\(["\'](\w+)["\']',  # Additional common patterns
            r'\.set\(["\'](\w+)["\']',
        ]
    ]

    # Common placeholder values to ignore
    PLACEHOLDER_VALUES = {
        "your_api_key", "xxx", "placeholder", "example", "changeme", "todo",
        "secret_key_here", "insert_key_here", "test", "demo", "sample",
        "fake", "dummy", "temp", "null", "undefined", "true", "false"
    }

    def __init__(self, config: Optional[ParserConfig] = None):
        self.config = config or ParserConfig()

    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid and not a data/javascript URI."""
        if not self.config.validate_urls:
            return True
            
        try:
            parsed = urlparse(url)
            if parsed.scheme in ('data', 'javascript', 'mailto', 'tel'):
                return False
            if parsed.netloc and '.' not in parsed.netloc and parsed.netloc != 'localhost':
                return False
            return True
        except:
            return False

    def _is_placeholder(self, value: str) -> bool:
        """Check if value appears to be a placeholder."""
        if not self.config.include_placeholders:
            value_lower = value.lower()
            return any(placeholder in value_lower for placeholder in self.PLACEHOLDER_VALUES)
        return False

    def extract_endpoints(self, js_text: str, base_url: str = "") -> Set[str]:
        """
        Parse JS source text and return a set of discovered endpoint URLs.
        """
        found: Set[str] = set()
        lines = js_text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.ENDPOINT_PATTERNS:
                matches = pattern.findall(line)
                for match in matches:
                    if not match or not match.strip():
                        continue
                    
                    # Clean the match
                    match = match.strip().rstrip('\\')
                    
                    if match.startswith("/"):
                        if base_url:
                            full_url = urljoin(base_url, match)
                            if self._is_valid_url(full_url):
                                found.add(full_url)
                        elif self._is_valid_url(match):
                            found.add(match)
                    elif match.startswith(("http://", "https://", "ws://", "wss://")):
                        if self._is_valid_url(match):
                            found.add(match)
                    elif base_url and not match.startswith(("data:", "javascript:", "#")):
                        full_url = urljoin(base_url, match)
                        if self._is_valid_url(full_url):
                            found.add(full_url)
        
        return found

    def extract_secrets(self, js_text: str) -> List[Dict[str, Any]]:
        """
        Scan JS source for hardcoded secrets, API keys, and tokens.
        Returns a list of dicts: [{label, value, severity}]
        """
        findings: List[Dict[str, Any]] = []
        lines = js_text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, label, severity in self.SECRET_PATTERNS:
                matches = pattern.findall(line)
                for match in matches:
                    if not match or not match.strip():
                        continue
                    
                    # Handle both string matches and tuple matches
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else (match[1] if len(match) > 1 else "")
                    
                    match = match.strip()
                    
                    # Skip placeholders and empty values
                    if not match or self._is_placeholder(match):
                        continue
                    
                    # Truncate long values
                    display_value = match[:self.config.max_secret_length]
                    if len(match) > self.config.max_secret_length:
                        display_value += "…"
                    
                    # Get some context around the finding
                    context_start = max(0, line.find(match) - 20)
                    context_end = min(len(line), line.find(match) + len(match) + 20)
                    context = line[context_start:context_end].strip()
                    
                    findings.append({
                        "label": label,
                        "value": display_value,
                        "severity": severity.value,
                        "context": context,
                        "line_number": line_num
                    })
        
        return findings

    def extract_hidden_params(self, js_text: str) -> Set[str]:
        """
        Find parameter names used in JS that don't appear in HTML forms.
        These are prime targets for injection testing.
        """
        params: Set[str] = set()
        
        for pattern in self.PARAM_PATTERNS:
            matches = pattern.findall(js_text)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else ""
                
                match = match.strip()
                
                # Validate parameter name
                if (self.config.min_param_length <= len(match) <= self.config.max_param_length and 
                    match.isidentifier() and not match.isdigit()):
                    params.add(match)
        
        return params

    def extract_all(self, js_text: str, base_url: str = "") -> Dict[str, Any]:
        """
        Extract all types of information from JS text in a single call.
        
        Returns:
            Dictionary containing endpoints, secrets, and hidden parameters
        """
        return {
            "endpoints": list(self.extract_endpoints(js_text, base_url)),
            "secrets": self.extract_secrets(js_text),
            "hidden_params": list(self.extract_hidden_params(js_text))
        }

    def analyze_js_file(self, file_path: str, base_url: str = "") -> Dict[str, Any]:
        """
        Analyze a JavaScript file and return all findings.
        
        Args:
            file_path: Path to the JavaScript file
            base_url: Base URL for relative endpoint resolution
            
        Returns:
            Dictionary with analysis results
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                js_content = f.read()
            
            return self.extract_all(js_content, base_url)
            
        except Exception as e:
            return {
                "endpoints": [],
                "secrets": [],
                "hidden_params": [],
                "error": f"Failed to read file: {str(e)}"
            }


# Singleton instance for backward compatibility
_js_parser: Optional[JSParser] = None

def get_js_parser(config: Optional[ParserConfig] = None) -> JSParser:
    """Get or create JSParser instance."""
    global _js_parser
    if _js_parser is None:
        _js_parser = JSParser(config)
    return _js_parser
