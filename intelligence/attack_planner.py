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

            if f_type == "XSS":
                actions.append({
                    "action": "steal_session",
                    "target": f["url"],
                    "priority": "high"
                })

            elif "SQL" in f_type:
                actions.append({
                    "action": "dump_database",
                    "target": f["url"],
                    "priority": "critical"
                })

            elif f_type == "IDOR":
                actions.append({
                    "action": "enumerate_ids",
                    "target": f["url"],
                    "priority": "high"
                })

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