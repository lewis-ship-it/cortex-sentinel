# scanner/priority_engine.py


class PriorityEngine:

    # -------------------------
    # KEYWORD LISTS
    # -------------------------
    HIGH_RISK = ["admin", "login", "auth", "account", "api", "checkout"]
    MEDIUM_RISK = ["search", "query", "filter"]

    # Attack selection keywords (merged from attack_planner.py)
    AUTH_KEYWORDS = ["login", "auth"]
    SEARCH_KEYWORDS = ["search", "query"]

    # -------------------------
    # SCORING
    # -------------------------
    def score_endpoint(self, url):
        score = 0

        for word in self.HIGH_RISK:
            if word in url:
                score += 5

        for word in self.MEDIUM_RISK:
            if word in url:
                score += 3

        # Parameter bonus — URLs with query strings are higher priority
        if "?" in url:
            score += 4

        return score

    # -------------------------
    # PRIORITIZE
    # -------------------------
    def prioritize(self, endpoints):
        scored = [(url, self.score_endpoint(url)) for url in endpoints]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [url for url, _ in scored]

    # -------------------------
    # CHOOSE ATTACKS
    # (moved from scanner/attack_planner.py)
    # -------------------------
    def choose_attacks(self, url):
        """
        Returns a list of attack types to run against a given URL
        based on the nature of the endpoint.
        """
        if any(k in url for k in self.AUTH_KEYWORDS):
            return ["sqli", "bruteforce"]

        if any(k in url for k in self.SEARCH_KEYWORDS):
            return ["xss", "sqli"]

        return ["xss"]