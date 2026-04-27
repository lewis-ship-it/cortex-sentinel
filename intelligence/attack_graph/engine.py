
# intelligence/attack_graph/engine.py
class AttackGraph:
    def __init__(self):
        self.nodes = []
        self.edges = []

    def add_node(self, vuln):
        node = {
            "id":         len(self.nodes),
            "type":       vuln.get("type"),
            "subtype":    vuln.get("subtype",""),
            "url":        vuln.get("url"),
            "severity":   vuln.get("severity"),
            "confidence": vuln.get("confidence", 0.5),
        }
        self.nodes.append(node)
        return node

    def build(self, findings):
        self.nodes = []
        self.edges = []
        for f in findings:
            self.add_node(f)
        for i, a in enumerate(self.nodes):
            for j, b in enumerate(self.nodes):
                if i == j: continue
                rel = self._can_chain(a, b)
                if rel:
                    self.edges.append({"from": a["id"], "to": b["id"], "type": rel})
        return {"nodes": self.nodes, "edges": self.edges}

    def _can_chain(self, a, b):
        at, bt = a["type"], b["type"]
        au, bu = a.get("url",""), b.get("url","")
        if "XSS" in at and "admin" in bu: return "session_hijack_to_admin"
        if "SQL" in at and "Sensitive" in bt: return "data_exfiltration"
        if "SQL" in at and "admin" in bu: return "auth_bypass_to_admin"
        if "SSTI" in at: return "potential_rce"
        if "LFI" in at and "SQL" in bt: return "credential_harvest"
        if "Open Redirect" in at and "XSS" in bt: return "phishing_chain"
        if "CORS" in at and "XSS" in bt: return "cross_origin_data_theft"
        if "login" in au and "admin" in bu: return "privilege_escalation"
        return None

    def find_attack_paths(self):
        paths = []
        for edge in self.edges:
            start = self.nodes[edge["from"]]
            end   = self.nodes[edge["to"]]
            if start["severity"] in ("Critical","High") or end["severity"] in ("Critical","High"):
                paths.append({"path": [start, end], "impact": edge["type"]})
        return paths

