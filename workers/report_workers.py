# workers/report_workers.py

import asyncio
import logging

from task_queue.redis_client import pop, retry
from task_queue.queues import REPORT_QUEUE, AGGREGATION_QUEUE
from scanner.ai_report import AIReportGenerator
from scanner.attack_graph import AttackGraph
from core.database import DatabaseManager
from core.job_tracker import update_stage
from core.aggregation_store import clear

ai           = AIReportGenerator()
db           = DatabaseManager()
graph_engine = AttackGraph()


async def main():
    while True:
        job = pop(REPORT_QUEUE)

        if not job:
            await asyncio.sleep(1)
            continue

        try:
            job_id   = job["job_id"]
            findings = job.get("findings", [])

            update_stage(job_id, "attack_graph", 85)

            # ── Build graph ───────────────────────────
            graph        = graph_engine.build(findings)
            attack_paths = graph_engine.find_attack_paths()

            update_stage(job_id, "ai_analysis", 92)

            # ── AI Report ─────────────────────────────
            report = await ai.generate_report({
                "findings":     findings,
                "attack_graph": graph,
                "chains":       attack_paths   # paths are the chains for this worker
            }, job_id)

            db.save_report(job_id, report)
            clear(job_id)

            update_stage(job_id, "done", 100)
            logging.info(f"[DONE] {job_id}")

        except Exception as e:
            retry(REPORT_QUEUE, job, str(e))


asyncio.run(main())