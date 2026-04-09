import asyncio
import logging
import httpx

from task_queue.redis_client import pop, retry
from task_queue.queues import SCAN_QUEUE
from core.orchestrator import Orchestrator

from scanner.dast.payload_mutator import PayloadMutator
from scanner.dast.priority_engine import PriorityEngine
from scanner.dast.param_engine import ParamEngine
from scanner.dast.rate_limiter import RateLimiter

mutator = PayloadMutator()
planner = PriorityEngine()
param_eng = ParamEngine()
limiter = RateLimiter()

orchestrator = Orchestrator()


async def smart_scan(url):
    findings = []
    attacks = planner.choose_attacks(url)

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for attack in attacks:
            if attack == "sqli":
                for payload in mutator.mutate("' OR 1=1--"):
                    limiter.wait(url)
                    # simplified
                    findings.append({"type": "SQLi", "url": url})

            if attack == "xss":
                for payload in mutator.mutate("<script>alert(1)</script>"):
                    limiter.wait(url)
                    findings.append({"type": "XSS", "url": url})

    return findings


async def main():
    while True:
        job = pop(SCAN_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue

        try:
            job_id = job["job_id"]
            url = job["url"]

            findings = await smart_scan(url)

            # ❌ NO direct aggregation push anymore

            await orchestrator.on_stage_complete(
                job_id,
                "scan",
                {"findings": findings}
            )

        except Exception as e:
            retry(SCAN_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())