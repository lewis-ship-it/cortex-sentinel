# utils/evasion.py
# WAF evasion / payload mutation utility.
# Used by injection modules to bypass simple WAF rules.

import urllib.parse
import random


class EvasionUtility:
    """
    Applies stealth transformations to payloads to bypass WAF pattern matching.

    level=0: no mutation (raw payload)
    level=1: light encoding (URL-encode special chars, case variation)
    level=2: aggressive (double encoding, comment insertion, whitespace tricks)
    """

    def apply_stealth(self, payload: str, level: int = 1) -> str:
        if level == 0:
            return payload
        if level == 1:
            return self._light(payload)
        return self._aggressive(payload)

    def _light(self, p: str) -> str:
        """URL-encode quotes and angle brackets."""
        return p.replace("'", "%27").replace('"', "%22").replace("<", "%3C").replace(">", "%3E")

    def _aggressive(self, p: str) -> str:
        """Double-encode + SQL comment insertion."""
        # Insert /**/ between SQL keywords
        for kw in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]:
            p = p.replace(kw, f"/**/{kw}/**/")
        # Double-encode
        p = urllib.parse.quote(urllib.parse.quote(p))
        return p

    def mutations(self, payload: str) -> list[str]:
        """Return all mutation variants for a payload."""
        return [
            payload,
            self._light(payload),
            self._aggressive(payload),
            payload.replace(" ", "/**/"),
            payload.replace(" ", "%09"),   # tab
            payload.replace(" ", "%0a"),   # newline
            urllib.parse.quote(payload),
        ]
