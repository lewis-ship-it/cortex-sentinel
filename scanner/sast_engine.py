
import zipfile
import os
import re
import logging
import shutil

class SASTScanner:
    def __init__(self):
        # 1. Expanded Patterns (The "Pattern Matcher" Limb)
        self.patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"([^A-Z0-9+/]|[A-Z0-9+/]{40}(?![A-Z0-9+/]))",
            "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
            "Firebase URL": r"https://.*\.firebaseio\.com",
            "Generic Password Variable": r"(?i)(password|passwd|pwd|secret|auth_token)\s*[:=]\s*['\"](.*)['\"]",
            "Database Connection String": r"(mongodb\+srv|postgres|mysql|sqlite):\/\/[^\s]+"
        }
        
        # 2. Dangerous Function Detection (Language Specific)
        self.dangerous_functions = {
            ".py": [r"eval\(", r"exec\(", r"os\.system\(", r"subprocess\.popen\("],
            ".js": [r"eval\(", r"innerHTML", r"document\.write\(", r"child_process\.exec\("],
            ".php": [r"shell_exec\(", r"system\(", r"passthru\(", r"base64_decode\("]
        }

    def scan_zip(self, zip_path, extract_to="temp_extraction"):
        findings = []
        # Ensure clean extraction directory
        if os.path.exists(extract_to):
            shutil.rmtree(extract_to)
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)

            for root, _, files in os.walk(extract_to):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Ignore non-text files and binary data
                    if any(file.endswith(ext) for ext in ['.png', '.jpg', '.exe', '.pyc']):
                        continue
                        
                    findings.extend(self.analyze_file(file_path))
        
        except Exception as e:
            logging.error(f"[SAST ERROR] Failed to process zip: {e}")
        finally:
            # We keep files temporarily for Gemini to read later if needed
            pass
            
        return findings

    def analyze_file(self, path):
        results = []
        ext = os.path.splitext(path)[1]
        
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()
                
                # Check for Hardcoded Secrets
                for name, pattern in self.patterns.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        results.append({
                            "type": "Hardcoded Secret",
                            "item": name,
                            "file": os.path.basename(path),
                            "severity": "High",
                            "evidence": match.group(0)[:50] # Snippet for the report
                        })

                # Check for Dangerous Functions (Code Injection Risks)
                if ext in self.dangerous_functions:
                    for pattern in self.dangerous_functions[ext]:
                        if re.search(pattern, content):
                            results.append({
                                "type": "Dangerous Function Call",
                                "item": pattern.replace('\\', ''),
                                "file": os.path.basename(path),
                                "severity": "Medium",
                                "description": "Potentially insecure function that could lead to Command Injection."
                            })
                            
        except Exception as e:
            logging.error(f"[SAST ERROR] Could not read {path}: {e}")
            
        return results

