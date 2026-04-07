import re


class JSParser:
    """
    Extracts API endpoints and URLs from JavaScript source files.
    """

    # Patterns to find paths/routes embedded in JS
    ENDPOINT_PATTERNS = [
        r'["\'](/api/[^\s"\'<>]+)["\']',
        r'["\'](/v\d+/[^\s"\'<>]+)["\']',
        r'fetch\(["\']([^\s"\'<>]+)["\']',
        r'axios\.\w+\(["\']([^\s"\'<>]+)["\']',
        r'url:\s*["\']([^\s"\'<>]+)["\']',
        r'href:\s*["\']([^\s"\'<>]+)["\']',
    ]

    def extract_endpoints(self, js_text, base_url=""):
        """
        Parse JS source text and return a set of discovered endpoint paths.
        """
        found = set()

        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.findall(pattern, js_text)
            for match in matches:
                # Only keep relative paths or same-origin URLs
                if match.startswith("/"):
                    from urllib.parse import urljoin
                    found.add(urljoin(base_url, match))
                elif base_url and match.startswith(base_url):
                    found.add(match)

        return found