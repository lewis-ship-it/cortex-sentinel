# scanner/dast/payload_mutator.py
# AGGRESSIVE PAYLOAD MUTATOR — Generates WAF-bypass variants of any payload
# Covers: URL encoding, double encoding, HTML entity, base64, comment breaking,
# case mangling, whitespace substitution, null byte, Unicode, and more

import urllib.parse
import base64
import html
import random


class PayloadMutator:
    def mutate(self, payload: str) -> list:
        """Generate all WAF-bypass variants of a payload."""
        variants = [payload]
        v = set()
        v.add(payload)

        # URL encoding
        encoded = urllib.parse.quote(payload)
        if encoded not in v:
            v.add(encoded)
            variants.append(encoded)

        # Double URL encoding
        double = urllib.parse.quote(urllib.parse.quote(payload))
        if double not in v:
            v.add(double)
            variants.append(double)

        # Partial URL encoding (only special chars)
        partial = payload.replace("<", "%3C").replace(">", "%3E").replace('"', "%22").replace("'", "%27")
        if partial not in v:
            v.add(partial)
            variants.append(partial)

        # HTML entity encoding
        html_enc = html.escape(payload)
        if html_enc not in v and html_enc != payload:
            v.add(html_enc)
            variants.append(html_enc)

        # Base64 encoding (for data: URIs)
        b64 = base64.b64encode(payload.encode()).decode()
        if b64 not in v:
            v.add(b64)
            variants.append(b64)

        # SQL comment breaking
        comment = payload.replace("SELECT", "SE/**/LECT").replace("UNION", "UN/**/ION")
        comment = comment.replace("OR", "/**/OR/**/").replace("AND", "/**/AND/**/")
        if comment not in v and comment != payload:
            v.add(comment)
            variants.append(comment)

        # Case alternation
        mangled = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        if mangled not in v and mangled != payload:
            v.add(mangled)
            variants.append(mangled)

        # Uppercase
        upper = payload.upper()
        if upper not in v and upper != payload:
            v.add(upper)
            variants.append(upper)

        # Lowercase
        lower = payload.lower()
        if lower not in v and lower != payload:
            v.add(lower)
            variants.append(lower)

        # Space to tab
        tab = payload.replace(" ", "\t")
        if tab not in v and tab != payload:
            v.add(tab)
            variants.append(tab)

        # Space to newline
        newline = payload.replace(" ", "\n")
        if newline not in v and newline != payload:
            v.add(newline)
            variants.append(newline)

        # Space to SQL comment
        sql_comment = payload.replace(" ", "/**/")
        if sql_comment not in v and sql_comment != payload:
            v.add(sql_comment)
            variants.append(sql_comment)

        # Space to plus
        plus = payload.replace(" ", "+")
        if plus not in v and plus != payload:
            v.add(plus)
            variants.append(plus)

        # Null byte in keywords
        if "script" in payload.lower():
            null_byte = payload.replace("script", "scri\x00pt")
            if null_byte not in v:
                v.add(null_byte)
                variants.append(null_byte)

        # Tab in keywords
        if "script" in payload.lower():
            tab_keyword = payload.replace("script", "scr\tipt")
            if tab_keyword not in v:
                v.add(tab_keyword)
                variants.append(tab_keyword)

        # Unicode escape for angle brackets
        unicode_payload = payload.replace("<", "\u003c").replace(">", "\u003e")
        if unicode_payload not in v and unicode_payload != payload:
            v.add(unicode_payload)
            variants.append(unicode_payload)

        # Hex encoding for SQL keywords
        hex_payload = payload.replace("OR", "0x4f52").replace("AND", "0x414e44")
        if hex_payload not in v and hex_payload != payload:
            v.add(hex_payload)
            variants.append(hex_payload)

        return variants

    def get_random_mutation(self, payload: str) -> str:
        """Return a single random mutation of the payload."""
        variants = self.mutate(payload)
        return random.choice(variants) if len(variants) > 1 else payload
