# scanner/detector.py

import difflib
import html
import logging


class Detector:

    def similarity(self, a, b):
        return difflib.SequenceMatcher(None, a, b).ratio()

    # -----------------------
    # SQLi Detection
    # -----------------------
    def detect_sqli(self, baseline, true_res, false_res, delay_res=None):

        base_len  = len(baseline.text)
        true_len  = len(true_res.text)
        false_len = len(false_res.text)

        diff_true  = abs(base_len - true_len)
        diff_false = abs(base_len - false_len)

        # Changed from print() to logging.debug so it doesn't pollute prod logs
        logging.debug(f"[DETECT] base={base_len}, true={true_len}, false={false_len}")

        # Length-based detection
        if diff_true > 50 and diff_false < diff_true:
            return True

        # Error-based
        errors = ["sql", "mysql", "syntax error", "warning"]
        if any(e in true_res.text.lower() for e in errors):
            return True

        # Time-based
        if delay_res and delay_res["delay"] > 4:
            return True

        return False

    # -----------------------
    # XSS Detection
    # -----------------------
    def detect_xss(self, response_text, payload):

        # Direct reflection
        if payload in response_text:
            return True

        # HTML-encoded reflection
        encoded = html.escape(payload)
        if encoded in response_text:
            return True

        return False