import json
import os

class LearningEngine:
    def __init__(self, path="learning.json"):
        self.path = path
        self.data = self.load()

    def load(self):
        if os.path.exists(self.path):
            with open(self.path, "r") as f:
                return json.load(f)
        return {
            "vulnerable_params": {},
            "high_risk_paths": {},
            "successful_payloads": {}
        }

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)

    def record_finding(self, finding):
        param = finding.get("parameter")
        url = finding.get("url", "")
        payload = finding.get("payload")

        if param:
            self.data["vulnerable_params"][param] = \
                self.data["vulnerable_params"].get(param, 0) + 1

        if url:
            for key in ["admin", "login", "api"]:
                if key in url:
                    self.data["high_risk_paths"][key] = \
                        self.data["high_risk_paths"].get(key, 0) + 1

        if payload:
            self.data["successful_payloads"][payload] = \
                self.data["successful_payloads"].get(payload, 0) + 1

        self.save()

    def get_priority_boost(self, url):
        score = 0

        for key, count in self.data["high_risk_paths"].items():
            if key in url:
                score += count

        return score