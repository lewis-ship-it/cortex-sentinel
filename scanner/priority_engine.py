# scanner/priority_engine.py

import re

class PriorityEngine:

    def score_endpoint(self, url):
        score = 0

        # High-risk keywords
        high_risk = ["admin", "login", "auth", "account", "api", "checkout"]
        medium_risk = ["search", "query", "filter"]

        for word in high_risk:
            if word in url:
                score += 5

        for word in medium_risk:
            if word in url:
                score += 3

        # Parameter bonus
        if "?" in url:
            score += 4

        return score

    def prioritize(self, endpoints):
        scored = [(url, self.score_endpoint(url)) for url in endpoints]
        scored.sort(key=lambda x: x[1], reverse=True)

        return [url for url, _ in scored]