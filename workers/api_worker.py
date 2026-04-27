
# workers/api_worker.py

import asyncio
import logging
from task_queue.redis_client import pop, push, retry_job as retry
from task_queue.queues import API_QUEUE, AGGREGATION_QUEUE
from scanner.api.api_engine import APIEngine
from core.job_tracker import update_stage
from workers.base_worker import push_log

engine = APIEngine()


async def main():
    logging.info("[API WORKER] Ready and listening...")
    while True:
        job = pop(API_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue

        job_id     = job.get("job_id")
        target_url = job.get("url") or job.get("target_url")
        auth_token = job.get("auth_token")
        spec_url   = job.get("spec_url")
        tier       = job.get("tier", "Basic")

        try:
            push_log(job_id, f"[API] Starting {tier} scan for {target_url}", tier=tier)
            update_stage(job_id, "api_scan", 10)

            findings = await engine.scan(
                base_url=target_url,
                auth_token=auth_token,
                spec_url=spec_url,
                tier=tier,
            )

            # Tier gate: cap Basic-tier result count
            if tier == "Basic":
                findings = findings[:15]
                push_log(job_id, "[API] Basic tier: results capped at 15.", tier=tier)

            logging.info(f"[API WORKER] {len(findings)} findings for {target_url}")
            update_stage(job_id, "api_scan_done", 50)

            push(AGGREGATION_QUEUE, {
                "job_id":   job_id,
                "findings": findings,
                "tier":     tier,
            })

        except Exception as e:
            logging.error(f"[API WORKER] Failed for {target_url}: {e}")
            push_log(job_id, f"[API] Error: {e}", tier=tier)
            # FIX: exponential back-off retry
            retry(API_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())

