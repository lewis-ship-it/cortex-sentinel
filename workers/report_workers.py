import asyncio

from task_queue.redis_client import pop, retry
from task_queue.queues import REPORT_QUEUE
from scanner.ai_report import AIReportGenerator
from scanner.attack_graph import AttackGraph
from core.database import DatabaseManager
from core.aggregation_store import clear
from core.orchestrator import Orchestrator

ai = AIReportGenerator()
db = DatabaseManager()
graph_engine = AttackGraph()
orchestrator = Orchestrator()


async def main():
    while True:
        job = pop(REPORT_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue

        try:
            job_id = job["job_id"]
            findings = job.get("findings", [])

            graph = graph_engine.build(findings)
            attack_paths = graph_engine.find_attack_paths()

            report = await ai.generate_report(
                {
                    "findings": findings,
                    "attack_graph": graph,
                    "chains": attack_paths,
                },
                job_id,
            )

            db.save_report(job_id, report)
            clear(job_id)

            # 🔥 FINAL SIGNAL
            await orchestrator.on_stage_complete(job_id, "report")

        except Exception as e:
            retry(REPORT_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())