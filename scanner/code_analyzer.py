import os
import re

class CodeAnalyzer:

    def scan_file(self, filepath):
        findings = []

        with open(filepath, "r", errors="ignore") as f:
            content = f.read()

        # SQL Injection patterns
        if re.search(r"SELECT .* \+ .*", content):
            findings.append(("SQL Injection Risk", filepath))

        # XSS
        if "innerHTML" in content:
            findings.append(("Potential XSS", filepath))

        # Hardcoded secrets
        if re.search(r"api_key\s*=\s*['\"]", content):
            findings.append(("Hardcoded API Key", filepath))

        return findings

    def scan_directory(self, path):
        results = []

        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith((".js", ".php", ".py", ".html")):
                    full = os.path.join(root, file)
                    results.extend(self.scan_file(full))

        return results