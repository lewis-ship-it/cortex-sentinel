# scanner/js_parser.py

import re
from urllib.parse import urljoin

class JSParser:

    def extract_endpoints(self, js_content, base_url):
        endpoints = set()

        # Common API patterns
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v1/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post)\(["\']([^"\']+)["\']',
            r'["\'](/[^"\']+\.php[^"\']*)["\']'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, js_content)

            for match in matches:
                if isinstance(match, tuple):
                    match = match[-1]

                full_url = urljoin(base_url, match)
                endpoints.add(full_url)

        return endpoints