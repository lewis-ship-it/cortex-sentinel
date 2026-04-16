# utils/remediation.py
# Enriches findings with remediation advice and references.

REMEDIATION_DB = {
    "SQL Injection": {
        "remediation": (
            "Use parameterised queries (prepared statements) exclusively. "
            "Never concatenate user input into SQL strings. "
            "Example (Python/SQLAlchemy): `db.execute(text('SELECT * FROM users WHERE id=:id'), {'id': user_id})`"
        ),
        "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
        "cwe": "CWE-89",
    },
    "Cross-Site Scripting (XSS)": {
        "remediation": (
            "HTML-encode all user-controlled output using a context-aware library. "
            "Implement a strict Content-Security-Policy (CSP) header. "
            "Use frameworks that auto-escape by default (React, Angular)."
        ),
        "reference": "https://owasp.org/www-community/attacks/xss/",
        "cwe": "CWE-79",
    },
    "Command Injection": {
        "remediation": (
            "Never pass user input to shell commands. "
            "Use language-native APIs instead of shell execution. "
            "If unavoidable, use an allowlist of permitted values and avoid shell=True."
        ),
        "reference": "https://owasp.org/www-community/attacks/Command_Injection",
        "cwe": "CWE-78",
    },
    "Local File Inclusion (LFI)": {
        "remediation": (
            "Validate and sanitise file path inputs against a strict allowlist. "
            "Use basename() to strip traversal sequences. "
            "Never pass raw user input to file open functions."
        ),
        "reference": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
        "cwe": "CWE-22",
    },
    "SSRF": {
        "remediation": (
            "Validate and allowlist URLs before making server-side requests. "
            "Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x). "
            "Use a dedicated egress proxy that enforces allowlist rules."
        ),
        "reference": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "cwe": "CWE-918",
    },
    "Open Redirect": {
        "remediation": (
            "Use relative URLs only, or validate the redirect target against a strict allowlist. "
            "Never redirect based on a raw user-supplied URL parameter."
        ),
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "cwe": "CWE-601",
    },
    "Server-Side Template Injection (SSTI)": {
        "remediation": (
            "Never render user-supplied strings as templates. "
            "Use sandboxed template environments and disable dangerous filters. "
            "Prefer passing data as template variables, not template source."
        ),
        "reference": "https://portswigger.net/web-security/server-side-template-injection",
        "cwe": "CWE-94",
    },
    "GraphQL Introspection Enabled": {
        "remediation": (
            "Disable introspection in production GraphQL deployments. "
            "Most frameworks provide a flag: e.g., `introspection=False` in Graphene/Strawberry."
        ),
        "reference": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
        "cwe": "CWE-200",
    },
    "Broken Authentication": {
        "remediation": (
            "Use a well-tested JWT library and always verify the signature algorithm. "
            "Reject tokens with alg=none. Set short expiry times and rotate signing keys."
        ),
        "reference": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "cwe": "CWE-287",
    },
    "Potential IDOR": {
        "remediation": (
            "Enforce object-level authorisation on every data access. "
            "Verify the authenticated user owns the requested resource before returning it. "
            "Use UUIDs instead of sequential integers where possible."
        ),
        "reference": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        "cwe": "CWE-639",
    },
    "Missing Security Header": {
        "remediation": (
            "Add the missing header to all HTTP responses via your web server or application middleware. "
            "Use securityheaders.com to verify your configuration."
        ),
        "reference": "https://owasp.org/www-project-secure-headers/",
        "cwe": "CWE-693",
    },
}

DEFAULT_REMEDIATION = {
    "remediation": "Review the finding and apply defence-in-depth principles. Consult OWASP guidelines.",
    "reference":   "https://owasp.org/",
    "cwe":         "CWE-0",
}


class RemediationUtility:
    def enrich_finding(self, finding: dict) -> dict:
        """
        Adds 'remediation', 'reference', and 'cwe' keys to a finding dict in-place.
        Matches on finding type prefix so partial matches work.
        """
        ftype = finding.get("type", "")
        advice = DEFAULT_REMEDIATION

        for key, data in REMEDIATION_DB.items():
            if key.lower() in ftype.lower() or ftype.lower() in key.lower():
                advice = data
                break

        finding.setdefault("remediation", advice["remediation"])
        finding.setdefault("reference",   advice["reference"])
        finding.setdefault("cwe",         advice["cwe"])
        return finding
