import zipfile
import os
import re

class SASTScanner:
    def __init__(self):
        # Secret detection patterns
        self.patterns = {
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Generic Secret": r"(?i)secret[_\s]*[:=][\s]*['\"]?([a-zA-Z0-9]{20,})['\"]?",
            "Database URL": r"mongodb\+srv:\/\/|postgres:\/\/|mysql:\/\/"
        }

    def scan_zip(self, zip_path, extract_to="temp_extraction"):
        findings = []
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)

            for root, _, files in os.walk(extract_to):
                for file in files:
                    file_path = os.path.join(root, file)
                    findings.extend(self.analyze_file(file_path))
        finally:
            # Clean up logic would go here
            pass
        return findings

    def analyze_file(self, path):
        results = []
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()
                for name, pattern in self.patterns.items():
                    if re.search(pattern, content):
                        results.append({
                            "type": "Hardcoded Secret",
                            "item": name,
                            "file": os.path.basename(path),
                            "severity": "High"
                        })
        except Exception: pass
        return results