
# workers/planner_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# AI-DRIVEN ATTACK PLANNER WORKER — Professional tier only
#
# FIXES vs previous version:
#   1. Only pushed new IDOR scan jobs for id= params — missed every other vuln class.
#   2. No use of AttackPlanner or AIBrain — these exist for exactly this purpose.
#   3. findings arrived as dict but was iterated as list — KeyError crash.
#   4. Pushed to SCAN_QUEUE without tier, job_id keys aligned — worker received
#      malformed jobs.
#   5. No logging — invisible in dashboard.
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import traceback

from workers.base_worker import worker_loop, push_log
from task_queue.queues import PLANNER_QUEUE, SCAN_QUEUE, EXPLOIT_QUEUE
from task_queue.redis_client import push
from core.logger import get_logger
from intelligence.attack_planner import AttackPlanner

logger  = get_logger("planner_worker")
planner = AttackPlanner()


def handle(job):
    job_id   = job["job_id"]
    tier     = job.get("tier", "Professional")
    raw      = job.get("findings", [])

    # Normalize findings
    if isinstance(raw, dict):
        findings = raw.get("findings", [])
        chains   = raw.get("chains", [])
        findings = findings + chains
    else:
        findings = raw

    push_log(job_id, f"[PLANNER] AI attack planning for {len(findings)} findings", tier=tier)

    try:
        # Prioritize and generate attack tasks
        tasks = planner.plan(findings)
        push_log(job_id, f"[PLANNER] Generated {len(tasks)} attack tasks", tier=tier)

        scan_tasks  = [t for t in tasks if t.get("type") == "scan"]
        exploit_tasks = [t for t in tasks if t.get("type") == "exploit"]
        browser_tasks = [t for t in tasks if t.get("type") == "browser"]

        # Queue derived scan tasks with full context
        for task in scan_tasks:
            url = task.get("url")
            if not url:
                continue
            push(SCAN_QUEUE, {
                "job_id":     job_id,
                "url":        url,
                "target_url": url,
                "tier":       tier,
                "source":     "planner",
            })

        # Queue follow-up exploit tasks
        for task in exploit_tasks:
            push(EXPLOIT_QUEUE, {
                "job_id":   job_id,
                "findings": [task],
                "tier":     tier,
                "source":   "planner",
            })

        push_log(
            job_id,
            f"[PLANNER] Queued {len(scan_tasks)} scan + {len(exploit_tasks)} exploit tasks",
            tier=tier,
        )

    except Exception as exc:
        tb = traceback.format_exc()
        logger.error(f"Planner worker failed: {exc}\n{tb}", job_id)
        push_log(job_id, f"[PLANNER] Error: {exc}", tier=tier)


if __name__ == "__main__":
    worker_loop(PLANNER_QUEUE, handle)

