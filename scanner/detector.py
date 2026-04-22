# scanner/detector.py
# ──────────────────────────────────────────────────────────────────────────────
# SENTINEL DETECTOR — Evidence-Gated, Oracle-Based vulnerability detection.
#
# Architecture:
#   • Detector  — multi-signal detection methods (XSS, SQLi, SSTI, LFI, …)
#   • Validator — secondary oracle verification; ONLY gates a True result when
#                 concrete execution evidence is present in the response.
#
# Key changes vs. previous version:
#   1. detect_differential() is DEPRECATED for primary detection.
#      It is preserved as a debug/research helper but must never be the sole
#      reason a finding is created.
#   2. Validator.verify() is the single gating function — callers MUST call it
#      and receive True before appending a finding to the list.
#   3. WAF/defence codes (403, 429, 500, 503) return BLOCKED_BY_DEFENSE, not
#      Vulnerable, so they are never surfaced as real findings.
#   4. Every verify() call produces a VerificationResult carrying:
#        - is_vulnerable  (bool)
#        - confidence     (0.0–1.0)
#        - evidence_snippet (str)
#        - method         (str — e.g. 'oracle_math', 'error_signature')
#        - blocked        (bool — True when a WAF/defence response is seen)
# ──────────────────────────────────────────────────────────────────────────────

import re
import html
import difflib
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# SIGNATURE DATABASES
# ─────────────────────────────────────────────────────────────────────────────

SQLI_ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"mysql_num_rows\(\)",
    r"mysql_fetch",
    r"supplied argument is not a valid mysql",
    r"unclosed quotation mark after the character string",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"odbc microsoft access driver",
    r"odbc sql server driver",
    r"sqlstate=",
    r"syntax error converting",
    r"\[sql server\]",
    r"mssql_",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg::syntaxerror",
    r"postgresql.*error",
    r"unterminated quoted string at or near",
    r"syntax error at or near",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    r"oracle.*driver",
    r"warning.*oci_",
    # SQLite
    r"sqlite3?",
    r"sqlite_array_query",
    # Generic
    r"sql syntax.*?mysql",
    r"warning.*?\Wpg_",
    r"valid mysql result",
    r"check the manual that corresponds to your (mysql|mariadb|sqlite|postgresql)",
    r"division by zero in sql",
    r"invalid column name",
    r"column '.*' does not exist",
    r"table '.*' doesn't exist",
    r"unknown column '.*' in",
    r"data truncated for column",
    r"supplied argument is not a valid mysql result",
    r"you have an error in your sql",
    r"operand should contain 1 column\(s\)",
]

PHP_ERROR_SIGNATURES = [
    r"parse error:.*php",
    r"fatal error:.*php",
    r"warning:.*php",
    r"notice:.*php",
    r"undefined (variable|index|offset|function|method|class)",
    r"call to undefined function",
    r"call to a member function.*on null",
    r"cannot use object of type stdclass as array",
    r"failed to open stream",
    r"include\(.*\): failed to open stream",
    r"require\(.*\): failed to open stream",
    r"no such file or directory",
    r"permission denied",
    r"stack trace:",
    r"php version",
    r"zend",
]

LFI_SIGNATURES = [
    r"root:.*:0:0:",
    r"\[extensions\]",
    r"\[boot loader\]",
    r"for 16-bit app support",
    r"<\?php",
    r"\$_GET|\$_POST|\$_REQUEST",
    r"DB_PASSWORD|DB_HOST|DB_USER",
    r"define\(.*'DB_",
]

# SSTI oracle map: payload → expected evaluated string in response
SSTI_ORACLE_MAP = {
    "{{7*7}}":    "49",
    "{{7*'7'}}":  "7777777",
    "${7*7}":     "49",
    "*{7*7}":     "49",
    "#{7*7}":     "49",
    "<%= 7*7 %>": "49",
}

CMDI_SIGNATURES = [
    r"uid=\d+\(\w+\)",
    r"root:x:0:0",
    r"volume serial number",
    r"directory of c:\\",
    r"nt authority\\system",
    r"\w+\\administrator",
    r"linux.*#\d+",
    r"darwin.*xnu",
]

SSRF_SIGNATURES = [
    r"ami-id",
    r"instance-id",
    r"local-ipv4",
    r"169\.254\.169\.254",
    r"computeMetadata",
    r"project-id",
    r"internal server error.*internal.*host",
]

XSS_SINK_PATTERNS = [
    r"<script[^>]*>.*?(alert|confirm|prompt|eval|document\.write)",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"onfocus\s*=",
    r"onblur\s*=",
    r"<iframe[^>]*srcdoc\s*=",
    r"javascript\s*:",
]

# HTTP status codes that signal a WAF or server-side defence — never Vulnerable
BLOCKED_STATUS_CODES = {403, 429, 500, 503}

# Minimum delay (seconds) to classify as time-based hit
TIME_THRESHOLD = 4.5

# Similarity threshold for deprecated differential detection
SIMILARITY_THRESHOLD = 0.15


# ─────────────────────────────────────────────────────────────────────────────
# VERIFICATION RESULT  — returned by Validator.verify()
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    """
    The single source of truth for whether a payload produced exploitation
    evidence.  Callers gate finding creation on `is_vulnerable == True`.
    """
    is_vulnerable:    bool
    confidence:       float = 0.0
    evidence_snippet: str   = ""
    method:           str   = "unknown"
    blocked:          bool  = False   # True → WAF/defence response, not a bug

    @classmethod
    def blocked_by_defense(cls, status_code: int) -> "VerificationResult":
        return cls(
            is_vulnerable=False,
            confidence=0.0,
            evidence_snippet=f"Request blocked (HTTP {status_code})",
            method="blocked_by_defense",
            blocked=True,
        )

    @classmethod
    def negative(cls, reason: str = "") -> "VerificationResult":
        return cls(is_vulnerable=False, evidence_snippet=reason, method="no_match")


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATOR  — oracle-based secondary verification
# ─────────────────────────────────────────────────────────────────────────────

class Validator:
    """
    Secondary verification layer.  The scan worker MUST call verify() after
    every injection attempt and only create a finding when is_vulnerable is True.

    Routing logic
    ─────────────
    verify() inspects the payload and `vuln_type` hint to select the correct
    oracle sub-method:

      • ssti        → oracle_math (check evaluated result, e.g. 49)
      • sqli_error  → error_signature (regex against known DB error strings)
      • sqli_time   → timing_analysis (delay vs threshold + consistency check)
      • sqli_bool   → boolean_differential (true vs false response comparison)
      • xss         → reflection_oracle (unencoded payload in response body)
      • lfi         → content_oracle (OS file content markers in body)
      • cmdi        → command_output_oracle (OS command output patterns)
      • redirect    → header_oracle (Location header value)
      • header      → header_oracle (X-Injected present in response)
      • ssrf        → content_oracle (cloud metadata markers)

    WAF / defence gate
    ──────────────────
    Any response with a status code in BLOCKED_STATUS_CODES is immediately
    returned as BLOCKED_BY_DEFENSE.  The calling code should record this as a
    WAF block log entry, never as a vulnerability finding.
    """

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _match_patterns(self, text: str, patterns: list) -> Optional[str]:
        tl = text.lower()
        for pat in patterns:
            if re.search(pat, tl, re.IGNORECASE | re.DOTALL):
                # Extract the actual matching fragment for the evidence snippet
                m = re.search(pat, tl, re.IGNORECASE | re.DOTALL)
                if m:
                    return m.group(0)[:120]
        return None

    def _extract_snippet(self, body: str, marker: str, window: int = 80) -> str:
        """Return up to `window` chars around `marker` inside `body`."""
        idx = body.lower().find(marker.lower())
        if idx == -1:
            return marker
        start = max(0, idx - 20)
        return body[start: start + window]

    # ── WAF gate ─────────────────────────────────────────────────────────────

    def check_blocked(self, status_code: int) -> Optional[VerificationResult]:
        """Return a BLOCKED_BY_DEFENSE result if the status code is defensive."""
        if status_code in BLOCKED_STATUS_CODES:
            return VerificationResult.blocked_by_defense(status_code)
        return None

    # ── Oracle sub-methods ───────────────────────────────────────────────────

    def oracle_math(self, body: str, payload: str) -> VerificationResult:
        """
        SSTI oracle: the payload must have *evaluated* — mere reflection is not
        sufficient.  We look for the computed result (e.g. 49 for {{7*7}}).
        """
        expected = SSTI_ORACLE_MAP.get(payload)
        if not expected:
            # Fallback: any 7*7 variant
            if "7*7" in payload and "49" in body:
                snippet = self._extract_snippet(body, "49")
                return VerificationResult(
                    is_vulnerable=True,
                    confidence=0.90,
                    evidence_snippet=snippet,
                    method="oracle_math",
                )
            return VerificationResult.negative("No SSTI oracle mapping for payload")

        if expected in body:
            # Explicitly confirm the payload was NOT merely reflected unchanged
            if payload in body and expected not in body.replace(payload, ""):
                # The only place expected appears is inside the reflected payload
                # string itself — not evaluated.
                return VerificationResult.negative(
                    f"Value '{expected}' only appears as part of reflected payload, not evaluated"
                )
            snippet = self._extract_snippet(body, expected)
            return VerificationResult(
                is_vulnerable=True,
                confidence=0.95,
                evidence_snippet=snippet,
                method="oracle_math",
            )

        return VerificationResult.negative(
            f"SSTI: expected '{expected}' not found in response"
        )

    def error_signature(self, body: str) -> VerificationResult:
        """SQLi error-based: match concrete DB error strings."""
        fragment = self._match_patterns(body, SQLI_ERROR_SIGNATURES)
        if fragment:
            return VerificationResult(
                is_vulnerable=True,
                confidence=0.92,
                evidence_snippet=fragment,
                method="error_signature",
            )
        return VerificationResult.negative("No DB error signature matched")

    def timing_analysis(
        self,
        delay: float,
        payload: str,
        threshold: float = TIME_THRESHOLD,
        baseline_delay: float = 0.0,
    ) -> VerificationResult:
        """
        Time-based blind SQLi oracle.

        Requirements for True:
          1. delay must exceed `threshold` (default 4.5 s).
          2. The injected delay must be correlated to the payload's sleep
             duration, not just general network latency.  We check that
             `delay - baseline_delay` is within 30 % of the payload's
             intended sleep seconds to reject coincidental latency spikes.
        """
        # Extract the intended sleep duration from the payload (default 6 s)
        sleep_seconds = 6.0
        m = re.search(r"(?:sleep|pg_sleep)\((\d+)\)", payload, re.IGNORECASE)
        if not m:
            m = re.search(r"DELAY '0:0:(\d+)'", payload, re.IGNORECASE)
        if m:
            sleep_seconds = float(m.group(1))

        net_delay = delay - baseline_delay  # subtract network baseline

        if net_delay < threshold:
            return VerificationResult.negative(
                f"Delay {delay:.2f}s (net {net_delay:.2f}s) < threshold {threshold}s"
            )

        # Correlation check: net_delay should be within 30 % of intended sleep
        lower = sleep_seconds * 0.70
        upper = sleep_seconds * 1.50  # allow for server overhead
        if not (lower <= net_delay <= upper):
            return VerificationResult.negative(
                f"Delay {net_delay:.2f}s not correlated to intended sleep {sleep_seconds}s "
                f"(expected {lower:.1f}–{upper:.1f}s) — likely network latency"
            )

        return VerificationResult(
            is_vulnerable=True,
            confidence=0.87,
            evidence_snippet=(
                f"Response delayed {delay:.2f}s (net {net_delay:.2f}s); "
                f"payload intended {sleep_seconds}s sleep"
            ),
            method="timing_analysis",
        )

    def boolean_differential(
        self,
        true_body: str,
        false_body: str,
        baseline_body: str = "",
    ) -> VerificationResult:
        """
        Boolean-based blind SQLi oracle.

        True result requires:
          1. Significant length difference between true/false responses.
          2. true_body closer in length to baseline than false_body (or vice
             versa) — confirming the application returns different data sets.
          3. Low similarity between true/false bodies (content differs).
        """
        true_len  = len(true_body)
        false_len = len(false_body)
        base_len  = len(baseline_body) if baseline_body else true_len

        length_delta = abs(true_len - false_len)
        if length_delta < 80:
            return VerificationResult.negative(
                f"Boolean: length delta {length_delta}b < 80b minimum"
            )

        sim = difflib.SequenceMatcher(
            None, true_body[:8000], false_body[:8000]
        ).ratio()

        if sim > 0.70:
            return VerificationResult.negative(
                f"Boolean: true/false similarity {sim:.2f} too high — responses look the same"
            )

        # Confirm directionality: true response should be closer to baseline
        base_vs_true  = abs(base_len - true_len)
        base_vs_false = abs(base_len - false_len)
        if base_vs_true >= base_vs_false and baseline_body:
            return VerificationResult.negative(
                "Boolean: false response is closer to baseline — injection may not be working"
            )

        return VerificationResult(
            is_vulnerable=True,
            confidence=min(0.5 + (1 - sim), 0.90),
            evidence_snippet=(
                f"Boolean differential: true={true_len}b false={false_len}b "
                f"delta={length_delta}b similarity={sim:.2f}"
            ),
            method="boolean_differential",
        )

    def reflection_oracle(self, body: str, payload: str) -> VerificationResult:
        """
        XSS oracle: payload must appear *unencoded* in the response body.
        Merely seeing the HTML-entity-encoded version is insufficient.
        """
        if payload in body:
            snippet = self._extract_snippet(body, payload[:40])
            return VerificationResult(
                is_vulnerable=True,
                confidence=0.95,
                evidence_snippet=snippet,
                method="reflection_oracle",
            )

        # HTML-decoded match — lower confidence (browser may still execute)
        decoded = html.unescape(payload)
        if decoded != payload and decoded in body:
            return VerificationResult(
                is_vulnerable=True,
                confidence=0.80,
                evidence_snippet=self._extract_snippet(body, decoded[:40]),
                method="reflection_oracle_html_decoded",
            )

        return VerificationResult.negative(
            "XSS: payload not reflected unencoded in response"
        )

    def content_oracle(self, body: str, signatures: list, label: str, baseline_body: str = "") -> VerificationResult:
        """
        Generic content oracle for LFI, CMDI, SSRF.
        A signature match is only valid if the pattern is NOT already present
        in the baseline response.
        """
        for pat in signatures:
            if re.search(pat, body, re.IGNORECASE):
                if baseline_body and re.search(pat, baseline_body, re.IGNORECASE):
                    continue  # already present before injection — not our doing
                m = re.search(pat, body, re.IGNORECASE)
                snippet = m.group(0)[:120] if m else pat
                return VerificationResult(
                    is_vulnerable=True,
                    confidence=0.92,
                    evidence_snippet=snippet,
                    method=f"content_oracle_{label}",
                )
        return VerificationResult.negative(f"{label}: no matching content signature")

    def header_oracle(self, headers: dict, vuln_type: str, payload: str) -> VerificationResult:
        """
        Oracle for redirect and header injection vulnerabilities.

        redirect → Location header must contain the injected domain.
        header   → X-Injected header must be present (response splitting success).
        """
        if vuln_type == "redirect":
            location = headers.get("location", "") or headers.get("Location", "")
            if location and any(p in location for p in ["evil.com", "attacker.com", "//evil"]):
                return VerificationResult(
                    is_vulnerable=True,
                    confidence=0.90,
                    evidence_snippet=f"Location: {location[:120]}",
                    method="header_oracle_redirect",
                )
            return VerificationResult.negative(
                f"Redirect: Location header value '{location}' not controlled"
            )

        if vuln_type == "header":
            if "x-injected" in {k.lower() for k in headers}:
                return VerificationResult(
                    is_vulnerable=True,
                    confidence=0.92,
                    evidence_snippet="X-Injected header present in response (CRLF injection confirmed)",
                    method="header_oracle_injection",
                )
            return VerificationResult.negative("Header injection: X-Injected not found in response headers")

        return VerificationResult.negative(f"header_oracle: unknown vuln_type '{vuln_type}'")

    # ── Primary gating method ────────────────────────────────────────────────

    def verify(
        self,
        *,
        vuln_type:      str,
        payload:        str,
        body:           str,
        status_code:    int            = 200,
        response_headers: dict         = None,
        delay:          float          = 0.0,
        baseline_body:  str            = "",
        baseline_delay: float          = 0.0,
        false_body:     str            = "",
    ) -> VerificationResult:
        """
        Single gating method for all vulnerability types.

        Parameters
        ──────────
        vuln_type        : one of xss / sqli_error / sqli_time / sqli_bool /
                           ssti / lfi / cmdi / redirect / header / ssrf
        payload          : the exact string injected into the parameter
        body             : response body (first 5000 chars recommended)
        status_code      : HTTP status of the response
        response_headers : dict of response headers
        delay            : elapsed seconds for this request
        baseline_body    : body of the un-injected baseline request
        baseline_delay   : elapsed seconds for the baseline request
        false_body       : for boolean SQLi — response body to the false payload

        Returns
        ───────
        VerificationResult — callers create a finding ONLY when is_vulnerable=True.
        """
        response_headers = response_headers or {}

        # ── WAF / defence gate (takes absolute priority) ──────────────────
        blocked = self.check_blocked(status_code)
        if blocked:
            logger.debug(
                f"[VALIDATOR] {vuln_type}/{payload[:30]} → BLOCKED_BY_DEFENSE "
                f"(HTTP {status_code})"
            )
            return blocked

        # ── Route to the appropriate oracle ──────────────────────────────
        if vuln_type == "ssti":
            result = self.oracle_math(body, payload)

        elif vuln_type == "sqli_error":
            result = self.error_signature(body)

        elif vuln_type == "sqli_time":
            result = self.timing_analysis(delay, payload, baseline_delay=baseline_delay)

        elif vuln_type == "sqli_bool":
            result = self.boolean_differential(body, false_body, baseline_body)

        elif vuln_type == "xss":
            result = self.reflection_oracle(body, payload)

        elif vuln_type == "lfi":
            result = self.content_oracle(body, LFI_SIGNATURES, "lfi", baseline_body)

        elif vuln_type == "cmdi":
            result = self.content_oracle(body, CMDI_SIGNATURES, "cmdi", baseline_body)

        elif vuln_type == "ssrf":
            result = self.content_oracle(body, SSRF_SIGNATURES, "ssrf", baseline_body)

        elif vuln_type == "xxe":
            # XXE oracle: look for file content or SSRF indicators in response
            XXE_INDICATORS = LFI_SIGNATURES + SSRF_SIGNATURES
            # Additional inline markers specific to XXE responses
            result = self.content_oracle(body, XXE_INDICATORS, "xxe", baseline_body)

        elif vuln_type in ("redirect", "header"):
            result = self.header_oracle(response_headers, vuln_type, payload)

        else:
            logger.warning(f"[VALIDATOR] Unknown vuln_type: '{vuln_type}' — returning negative")
            result = VerificationResult.negative(f"Unknown vuln_type: {vuln_type}")

        logger.debug(
            f"[VALIDATOR] {vuln_type}/{payload[:30]!r} → "
            f"{'VULN' if result.is_vulnerable else 'SAFE'} "
            f"conf={result.confidence:.2f} method={result.method}"
        )
        return result


# ─────────────────────────────────────────────────────────────────────────────
# DETECTOR  — multi-signal detection helpers (used by scan_worker for signals;
#             final gate is always Validator.verify())
# ─────────────────────────────────────────────────────────────────────────────

class Detector:
    """
    Multi-signal vulnerability detector.

    These methods produce preliminary signals that the scan worker can use to
    decide whether to run a Validator.verify() call.  They should NOT be used
    to create findings directly.
    """

    def similarity(self, a: str, b: str) -> float:
        return difflib.SequenceMatcher(None, a[:8000], b[:8000]).ratio()

    def _match_patterns(self, text: str, patterns: list) -> Optional[str]:
        tl = text.lower()
        for pat in patterns:
            if re.search(pat, tl, re.IGNORECASE | re.DOTALL):
                return pat
        return None

    # ── XSS ─────────────────────────────────────────────────────────────────

    def detect_xss(self, response_text: str, payload: str) -> Optional[dict]:
        rt = response_text

        if payload in rt:
            return {"confidence": 0.95, "evidence": f"Payload reflected unencoded: {payload[:60]}"}

        decoded = html.unescape(payload)
        if decoded != payload and decoded in rt:
            return {"confidence": 0.80, "evidence": f"Payload reflected after HTML decode: {decoded[:60]}"}

        try:
            import urllib.parse
            url_decoded = urllib.parse.unquote(payload)
            if url_decoded != payload and url_decoded in rt:
                return {"confidence": 0.80, "evidence": f"Payload reflected after URL decode: {url_decoded[:60]}"}
        except Exception:
            pass

        dangerous_parts = ["<script", "onerror=", "onload=", "javascript:", "alert(", "confirm("]
        for part in dangerous_parts:
            if part.lower() in payload.lower() and part.lower() in rt.lower():
                return {"confidence": 0.65, "evidence": f"Dangerous payload fragment reflected: {part}"}

        for pat in XSS_SINK_PATTERNS:
            if re.search(pat, rt, re.IGNORECASE | re.DOTALL):
                if any(c in rt for c in ["alert", "confirm", "prompt"]):
                    return {"confidence": 0.70, "evidence": f"JS sink pattern detected: {pat}"}

        return None

    # ── SQLi ─────────────────────────────────────────────────────────────────

    def detect_sqli_error(self, response_text: str) -> Optional[dict]:
        matched = self._match_patterns(response_text, SQLI_ERROR_SIGNATURES)
        if matched:
            return {"confidence": 0.92, "evidence": f"DB error pattern: {matched}"}
        return None

    def detect_sqli_boolean(self, baseline: str, true_res: str, false_res: str) -> Optional[dict]:
        base_len  = len(baseline)
        true_len  = len(true_res)
        false_len = len(false_res)

        if abs(true_len - false_len) > 80 and abs(base_len - false_len) < abs(base_len - true_len):
            sim = self.similarity(true_res, false_res)
            return {
                "confidence": min(0.5 + (1 - sim), 0.90),
                "evidence": f"Boolean differential: true={true_len}b false={false_len}b sim={sim:.2f}"
            }

        sim = self.similarity(true_res, false_res)
        if sim < SIMILARITY_THRESHOLD:
            return {"confidence": 0.75, "evidence": f"Boolean response similarity too low: {sim:.2f}"}

        return None

    def detect_sqli_time(self, delay: float, threshold: float = TIME_THRESHOLD) -> Optional[dict]:
        if delay >= threshold:
            return {
                "confidence": 0.85,
                "evidence": f"Response delayed {delay:.2f}s ≥ threshold {threshold}s"
            }
        return None

    def detect_sqli(self, baseline_text: str, attack_text: str, delay: float = 0.0) -> Optional[dict]:
        hit = self.detect_sqli_error(attack_text)
        if hit:
            hit["method"] = "error-based"
            return hit
        bool_hit = self.detect_sqli_boolean(baseline_text, attack_text, "")
        if bool_hit:
            bool_hit["method"] = "boolean-based"
            return bool_hit
        time_hit = self.detect_sqli_time(delay)
        if time_hit:
            time_hit["method"] = "time-based-blind"
            return time_hit
        return None

    # ── PHP errors ───────────────────────────────────────────────────────────

    def detect_php_error(self, response_text: str) -> Optional[dict]:
        matched = self._match_patterns(response_text, PHP_ERROR_SIGNATURES)
        if matched:
            for line in response_text.splitlines():
                if re.search(matched, line, re.IGNORECASE):
                    return {"confidence": 0.90, "evidence": f"PHP error: {line[:120].strip()}"}
            return {"confidence": 0.85, "evidence": f"PHP error pattern: {matched}"}
        return None

    # ── LFI ──────────────────────────────────────────────────────────────────

    def detect_lfi(self, response_text: str, baseline_text: str = "") -> Optional[dict]:
        for pat in LFI_SIGNATURES:
            if re.search(pat, response_text, re.IGNORECASE):
                if baseline_text and re.search(pat, baseline_text, re.IGNORECASE):
                    continue
                return {"confidence": 0.90, "evidence": f"LFI indicator: {pat}"}
        return None

    # ── SSTI ─────────────────────────────────────────────────────────────────

    def detect_ssti(self, response_text: str, payload: str) -> Optional[dict]:
        """
        Preliminary SSTI signal — always back this with Validator.verify()
        using vuln_type='ssti' before creating a finding.
        """
        expected = SSTI_ORACLE_MAP.get(payload)
        if expected and expected in response_text:
            return {
                "confidence": 0.95,
                "evidence": f"SSTI: payload {payload!r} evaluated to {expected!r}"
            }
        if "49" in response_text and "7*7" in payload:
            return {"confidence": 0.90, "evidence": "Math expression {{7*7}} evaluated to 49"}
        return None

    # ── Command injection ────────────────────────────────────────────────────

    def detect_cmdi(self, response_text: str, baseline_text: str = "") -> Optional[dict]:
        for pat in CMDI_SIGNATURES:
            if re.search(pat, response_text, re.IGNORECASE):
                if baseline_text and re.search(pat, baseline_text, re.IGNORECASE):
                    continue
                return {"confidence": 0.92, "evidence": f"Command output: {pat}"}
        return None

    # ── SSRF ─────────────────────────────────────────────────────────────────

    def detect_ssrf(self, response_text: str, status_code: int = 200) -> Optional[dict]:
        matched = self._match_patterns(response_text, SSRF_SIGNATURES)
        if matched:
            return {"confidence": 0.88, "evidence": f"SSRF indicator: {matched}"}
        return None

    # ── Open redirect ────────────────────────────────────────────────────────

    def detect_open_redirect(self, response_headers: dict, payload: str) -> Optional[dict]:
        location = response_headers.get("Location", "") or response_headers.get("location", "")
        if location and any(p in location for p in ["evil.com", "attacker.com", "//evil"]):
            return {"confidence": 0.88, "evidence": f"Location header redirects to: {location}"}
        if "evil.com" in location or payload.replace("//", "") in location:
            return {"confidence": 0.80, "evidence": f"Redirect to injected domain: {location}"}
        return None

    # ── Header injection ─────────────────────────────────────────────────────

    def detect_header_injection(self, response_headers: dict) -> Optional[dict]:
        injected = response_headers.get("X-Injected", "")
        if injected:
            return {
                "confidence": 0.90,
                "evidence": "X-Injected header successfully reflected in response"
            }
        return None

    # ── Info disclosure ──────────────────────────────────────────────────────

    INFO_PATTERNS = [
        (r"aws_access_key_id\s*=\s*[A-Z0-9]{20}", "AWS Access Key"),
        (r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}", "AWS Secret Key"),
        (r"password\s*=\s*['\"][^'\"]{6,}", "Password in response"),
        (r"db_password\s*=\s*['\"][^'\"]+", "DB password disclosed"),
        (r"secret_key\s*=\s*['\"][^'\"]+", "Secret key disclosed"),
        (r"api_key\s*=\s*['\"][^'\"]+", "API key disclosed"),
        (r"private_key.*BEGIN", "Private key disclosed"),
        (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private key in response"),
        (r"eyJ[A-Za-z0-9+/=]{20,}", "JWT token in response"),
        (r"[0-9a-f]{32}", "MD5 hash exposed"),
        (r"X-Powered-By: PHP", "PHP version header"),
        (r"Server: Apache/\d", "Apache version disclosed"),
        (r"X-AspNet-Version", "ASP.NET version disclosed"),
        (r"\bphp\b.*\b(5\.\d|7\.[0-2])\b", "Outdated PHP version"),
    ]

    def detect_info_disclosure(self, response_text: str, response_headers: dict = None) -> list:
        findings = []
        combined = response_text
        if response_headers:
            combined += "\n" + "\n".join(f"{k}: {v}" for k, v in response_headers.items())
        for pat, label in self.INFO_PATTERNS:
            m = re.search(pat, combined, re.IGNORECASE)
            if m:
                findings.append({
                    "type":       "Information Disclosure",
                    "subtype":    label,
                    "severity":   "High",
                    "confidence": 0.85,
                    "evidence":   m.group(0)[:80],
                })
        return findings

    # ── DEPRECATED — differential detection ──────────────────────────────────

    def detect_differential(self, baseline: str, attack: str, label: str = "Unknown") -> Optional[dict]:
        """
        DEPRECATED — do NOT use this method as the sole basis for creating a
        finding.  It generates too many false positives from harmless content
        changes (personalisation, CSRF tokens, timestamps, A/B testing, etc.).

        Retained for research/debug use only.  Scan worker pipelines must gate
        all findings through Validator.verify() instead.
        """
        logger.debug(
            f"[DEPRECATED] detect_differential called for '{label}' — "
            "this method must not create findings directly."
        )
        sim = self.similarity(baseline, attack)
        if sim < 0.45:
            return {
                "confidence": 0.50 + (0.45 - sim),
                "evidence": f"[DEPRECATED differential] similarity={sim:.2f}",
                "_deprecated": True,
            }
        if baseline and abs(len(attack) - len(baseline)) / max(len(baseline), 1) > 0.30:
            return {
                "confidence": 0.55,
                "evidence": f"[DEPRECATED differential] length shifted by {abs(len(attack)-len(baseline))}b",
                "_deprecated": True,
            }
        return None



# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL EVIDENCE GATE
# FIX: validate_evidence() was imported by exploit_worker but never defined.
# ─────────────────────────────────────────────────────────────────────────────

def validate_evidence(finding: dict) -> bool:
    """
    Module-level evidence gate used by exploit_worker.
    Returns True only if the finding carries a valid, method-backed evidence object.

    A finding passes if:
      1. It has an 'evidence' key that is either a non-empty string or a dict
         with a non-empty 'method' key.
      2. The evidence does not contain a 'no snippet provided' placeholder.
    """
    evidence = finding.get("evidence")
    if not evidence:
        return False
    if isinstance(evidence, str):
        lowered = evidence.lower()
        return bool(evidence.strip()) and "no snippet provided" not in lowered
    if isinstance(evidence, dict):
        method  = evidence.get("method", "")
        snippet = evidence.get("snippet", "")
        return bool(method) and "no snippet provided" not in snippet.lower()
    return False