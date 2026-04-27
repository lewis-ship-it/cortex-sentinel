
# scanner/dast/priority_engine.py
class PriorityEngine:
    HIGH_RISK   = ["admin","login","auth","account","api","checkout","user","password","upload","file"]
    MEDIUM_RISK = ["search","query","filter","find","id","view","page"]

    def score_endpoint(self, url: str) -> int:
        score = 0
        url_l = url.lower()
        for w in self.HIGH_RISK:
            if w in url_l: score += 5
        for w in self.MEDIUM_RISK:
            if w in url_l: score += 3
        if "?" in url: score += 4
        return score

    def prioritize(self, endpoints: list) -> list:
        scored = [(u, self.score_endpoint(u)) for u in endpoints]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [u for u, _ in scored]

    def choose_attacks(self, url: str) -> list:
        url_l = url.lower()
        attacks = ["xss"]
        if any(k in url_l for k in ["login","auth","user","password","account"]):
            attacks = ["sqli","xss","lfi"]
        elif any(k in url_l for k in ["search","query","find","q=","s="]):
            attacks = ["xss","sqli","ssti"]
        elif any(k in url_l for k in ["file","path","dir","doc","download"]):
            attacks = ["lfi","xss"]
        elif any(k in url_l for k in ["redirect","next","return","dest","url"]):
            attacks = ["open_redirect","xss"]
        return attacks


