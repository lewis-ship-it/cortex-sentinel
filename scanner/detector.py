class Detector:
    def detect_sqli(self, text, baseline, duration, mode):
        if mode == "time" and duration > 4:
            return True
        if "sql" in text.lower() and text != baseline:
            return True
        return False

    def detect_xss(self, text, payload):
        return payload in text