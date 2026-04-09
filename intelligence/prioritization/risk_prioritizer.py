class RiskPrioritizer:

    def __init__(self):
        # Base weights
        self.severity_weight = {
            "Critical": 90,
            "High": 70,
            "Medium": 50,
            "Low": 30
        }

        # Endpoint sensitivity
        self.sensitive_keywords = [
            "admin", "login", "auth", "account", "checkout", "api"
        ]

    def endpoint_score(self, url):
        score = 0
        for k in self.sensitive_keywords:
            if k in url.lower():
                score += 10
        return score

    def chain_boost(self, vuln_id, chains):
        for chain in chains:
            if vuln_id in chain:
                return 20
        return 0

    def calculate(self, findings, chains):
        prioritized = []

        for i, f in enumerate(findings):
            base = self.severity_weight.get(f.get("severity", "Low"), 20)

            endpoint_bonus = self.endpoint_score(f.get("url", ""))
            chain_bonus = self.chain_boost(str(i), chains)

            score = base + endpoint_bonus + chain_bonus

            prioritized.append({
                **f,
                "priority_score": min(score, 100),
                "fix_first": score >= 85
            })

        # Sort descending
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)

        return prioritized