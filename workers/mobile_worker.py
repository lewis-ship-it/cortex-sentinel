import asyncio

from task_queue.redis_client import pop, retry
from task_queue.queues import EXPLOIT_QUEUE
from scanner.exploit_engine import ExploitEngine
from core.orchestrator import Orchestrator

engine = ExploitEngine()
orchestrator = Orchestrator()


async def main():
    while True:
        job = pop(EXPLOIT_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue

        try:
            job_id = job["job_id"]
            findings = job.get("data", {}).get("findings", [])

            validated = await engine.verify(findings)

            await orchestrator.on_stage_complete(
                job_id,
                "exploit",
                {"findings": validated}
            )

        except Exception as e:
            retry(EXPLOIT_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())