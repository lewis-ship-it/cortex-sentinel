# intelligence/attack_planner.py

import random


class AttackPlanner:

    def __init__(self):
        pass

    # ─────────────────────────────────────────────
    # PRIORITIZATION
    # ─────────────────────────────────────────────
    def prioritize(self, findings):
        severity_order = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Info": 0
        }

        return sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity", "Low"), 0),
            reverse=True
        )

    # ─────────────────────────────────────────────
    # DECISION ENGINE
    # ─────────────────────────────────────────────
    def decide_next_actions(self, findings):
        actions = []

        for f in findings:
            f_type = f.get("type", "")
            url    = f.get("url") or f.get("target_url", "")

            if "XSS" in f_type or "Cross-Site Scripting" in f_type:
                actions.append({"action": "steal_session", "target": url, "priority": "high", "vuln_type": f_type})

            elif "SQL" in f_type:
                actions.append({"action": "dump_database", "target": url, "priority": "critical", "vuln_type": f_type})

            elif "IDOR" in f_type or "Direct Object" in f_type:
                actions.append({"action": "enumerate_ids", "target": url, "priority": "high", "vuln_type": f_type})

            elif "SSRF" in f_type:
                actions.append({"action": "pivot_internal", "target": url, "priority": "critical", "vuln_type": f_type})

            elif "Command Injection" in f_type or "CMDI" in f_type:
                actions.append({"action": "remote_execution", "target": url, "priority": "critical", "vuln_type": f_type})

            elif "Template Injection" in f_type or "SSTI" in f_type:
                actions.append({"action": "template_rce", "target": url, "priority": "critical", "vuln_type": f_type})

            elif "File Inclusion" in f_type or "LFI" in f_type:
                actions.append({"action": "read_sensitive_files", "target": url, "priority": "critical", "vuln_type": f_type})

            elif "XXE" in f_type:
                actions.append({"action": "xxe_exfil", "target": url, "priority": "critical", "vuln_type": f_type})

            elif "Broken Access" in f_type:
                actions.append({"action": "privilege_escalation", "target": url, "priority": "critical", "vuln_type": f_type})

            elif "Open Redirect" in f_type:
                actions.append({"action": "phishing_chain", "target": url, "priority": "medium", "vuln_type": f_type})

            elif "Missing Security Header" in f_type:
                actions.append({"action": "document_hardening_gap", "target": url, "priority": "low", "vuln_type": f_type})

            elif "Race Condition" in f_type:
                actions.append({"action": "exploit_race", "target": url, "priority": "high", "vuln_type": f_type})

            elif "Mass Assignment" in f_type:
                actions.append({"action": "privilege_via_mass_assign", "target": url, "priority": "high", "vuln_type": f_type})

        return actions

    # ─────────────────────────────────────────────
    # GENERATE NEW TASKS
    # ─────────────────────────────────────────────
    def generate_tasks(self, actions):
        tasks = []

        for action in actions:
            if action["action"] == "enumerate_ids":
                base = action["target"]

                for i in range(1, 10):
                    tasks.append({
                        "type": "scan",
                        "url": base.replace("id=1", f"id={i}")
                    })

            elif action["action"] == "dump_database":
                tasks.append({
                    "type": "exploit",
                    "technique": "sqli_deep",
                    "url": action["target"]
                })

            elif action["action"] == "steal_session":
                tasks.append({
                    "type": "browser",
                    "url": action["target"]
                })

        return tasks

    # ─────────────────────────────────────────────
    # FULL PIPELINE
    # ─────────────────────────────────────────────
    def plan(self, findings):
        prioritized = self.prioritize(findings)
        actions = self.decide_next_actions(prioritized)
        tasks = self.generate_tasks(actions)

        return tasks