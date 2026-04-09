class AttackGraph:
    def __init__(self):
        self.nodes = []
        self.edges = []

    # -------------------------
    # ADD NODE
    # -------------------------
    def add_node(self, vuln):
        node = {
            "id": len(self.nodes),
            "type": vuln.get("type"),
            "url": vuln.get("url"),
            "severity": vuln.get("severity"),
            "confidence": vuln.get("confidence", 0.5)
        }
        self.nodes.append(node)
        return node

    # -------------------------
    # BUILD GRAPH
    # -------------------------
    def build(self, findings):
        self.nodes = []
        self.edges = []

        for f in findings:
            self.add_node(f)

        for i in range(len(self.nodes)):
            for j in range(len(self.nodes)):

                if i == j:
                    continue

                a = self.nodes[i]
                b = self.nodes[j]

                relation = self.can_chain(a, b)

                if relation:
                    self.edges.append({
                        "from": a["id"],
                        "to": b["id"],
                        "type": relation
                    })

        return {
            "nodes": self.nodes,
            "edges": self.edges
        }

    # -------------------------
    # CHAIN LOGIC
    # -------------------------
    def can_chain(self, a, b):

        # XSS → Session Hijack → Auth Access
        if a["type"] == "Cross-Site Scripting (XSS)" and "admin" in b["url"]:
            return "session_hijack"

        # SQLi → Data Exposure
        if a["type"] == "SQL Injection" and b["type"] == "Sensitive Data Exposure":
            return "data_exfiltration"

        # Auth → Admin
        if "login" in a["url"] and "admin" in b["url"]:
            return "privilege_escalation"

        return None

    # -------------------------
    # FIND CRITICAL CHAINS
    # -------------------------
    def find_attack_paths(self):
        paths = []

        for edge in self.edges:
            start = self.nodes[edge["from"]]
            end = self.nodes[edge["to"]]

            if start["severity"] == "Critical" or end["severity"] == "Critical":
                paths.append({
                    "path": [start, end],
                    "impact": edge["type"]
                })

        return paths