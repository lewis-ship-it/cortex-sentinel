import asyncio

from task_queue.redis_client import pop, retry
from task_queue.queues import AGGREGATION_QUEUE
from core.aggregation_store import add_findings, get_findings
from core.orchestrator import Orchestrator

orchestrator = Orchestrator()


async def main():
    while True:
        job = pop(AGGREGATION_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue

        try:
            job_id = job["job_id"]
            findings = job.get("data", {}).get("findings", [])

            add_findings(job_id, findings)

            all_findings = get_findings(job_id)

            await orchestrator.on_stage_complete(
                job_id,
                "aggregation",
                {"findings": all_findings}
            )

        except Exception as e:
            retry(AGGREGATION_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())