# scanner/detector.py

import difflib
import html

class Detector:

    def similarity(self, a, b):
        return difflib.SequenceMatcher(None, a, b).ratio()

    # -----------------------
    # SQLi Detection (Verified)
    # -----------------------
    def detect_sqli(self, baseline, true_res, false_res, delay_res=None):

        base = baseline.text
        t = true_res.text
        f = false_res.text

        sim_true = self.similarity(base, t)
        sim_false = self.similarity(base, f)

        # Debug
        print(f"[DEBUG][SQLi] sim_true={sim_true}, sim_false={sim_false}")

        # Boolean-based detection
        if sim_true < 0.9 and sim_false > sim_true:
            return True

        # Error-based
        errors = ["sql", "mysql", "syntax error"]
        if any(e in t.lower() for e in errors):
            return True

        # Time-based verification
        if delay_res and delay_res["delay"] > 4:
            return True

        return False

    # -----------------------
    # XSS Detection (Verified)
    # -----------------------
    def detect_xss(self, response_text, payload):

        # direct reflection
        if payload in response_text:
            return True

        # HTML encoded reflection
        encoded = html.escape(payload)
        if encoded in response_text:
            return True

        return False