# scanner/ai_report.py

import os
from datetime import datetime

class AIReportGenerator:

    def __init__(self):
        pass

    # -----------------------
    # MAIN ENTRY
    # -----------------------
    def generate_report(self, findings, target):
        report = {
            "target": target,
            "generated_at": str(datetime.utcnow()),
            "summary": self.build_summary(findings),
            "details": []
        }

        for vuln in findings:
            report["details"].append(
                self.analyze_vulnerability(vuln)
            )

        return report

    # -----------------------
    # SUMMARY
    # -----------------------
    def build_summary(self, findings):
        summary = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for f in findings:
            sev = f.get("severity", "low").lower()
            if sev in summary:
                summary[sev] += 1

        return summary

    # -----------------------
    # CORE ANALYSIS
    # -----------------------
    def analyze_vulnerability(self, vuln):
        vuln_type = vuln.get("type", "Unknown")

        return {
            "type": vuln_type,
            "url": vuln.get("url"),
            "severity": vuln.get("severity"),
            "cvss": vuln.get("cvss"),

            "description": self.describe(vuln_type),
            "impact": self.impact(vuln_type),
            "exploit": self.exploit(vuln),
            "fix": self.fix(vuln_type)
        }

    # -----------------------
    # DESCRIPTIONS
    # -----------------------
    def describe(self, vuln_type):
        descriptions = {
            "SQL Injection": "Unsanitized user input is directly used in SQL queries.",
            "XSS": "User input is reflected into the page without proper escaping.",
            "DOM XSS": "JavaScript dynamically injects unsafe data into the DOM."
        }
        return descriptions.get(vuln_type, "Unknown vulnerability")

    # -----------------------
    # IMPACT
    # -----------------------
    def impact(self, vuln_type):
        impacts = {
            "SQL Injection": "Attackers can access, modify, or delete database data.",
            "XSS": "Attackers can execute scripts in victims' browsers.",
            "DOM XSS": "Client-side scripts can be hijacked."
        }
        return impacts.get(vuln_type, "Unknown impact")

    # -----------------------
    # EXPLOIT GENERATION
    # -----------------------
    def exploit(self, vuln):
        if vuln["type"] == "SQL Injection":
            return {
                "example_payload": "' OR 1=1--",
                "steps": [
                    "Inject payload into parameter",
                    "Observe altered response",
                    "Extract database data using UNION queries"
                ]
            }

        if vuln["type"] == "XSS":
            return {
                "example_payload": "<script>alert(document.cookie)</script>",
                "steps": [
                    "Inject script into input field",
                    "Wait for victim to load page",
                    "Steal session cookies"
                ]
            }

        return {"note": "No exploit available"}

    # -----------------------
    # FIXES
    # -----------------------
    def fix(self, vuln_type):
        fixes = {
            "SQL Injection": [
                "Use parameterized queries",
                "Validate input strictly",
                "Use ORM frameworks"
            ],
            "XSS": [
                "Escape all user input",
                "Use CSP headers",
                "Sanitize output"
            ],
            "DOM XSS": [
                "Avoid innerHTML",
                "Use safe DOM APIs"
            ]
        }

        return fixes.get(vuln_type, ["Manual review required"])