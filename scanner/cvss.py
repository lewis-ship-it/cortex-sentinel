# scanner/cvss.py

class CVSS:

    def calculate(self, vuln_type):
        base_scores = {
            "SQL Injection": 9.8,
            "XSS": 6.1,
            "DOM XSS": 7.5,
            "Form Issue": 5.0
        }

        return base_scores.get(vuln_type, 4.0)

    def severity_label(self, score):
        if score >= 9:
            return "Critical"
        elif score >= 7:
            return "High"
        elif score >= 4:
            return "Medium"
        else:
            return "Low"