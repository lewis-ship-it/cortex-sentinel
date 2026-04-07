# workers/api_worker.py

import asyncio
import logging

from task_queue.redis_client import pop, push, retry
from task_queue.queues import API_QUEUE, AGGREGATION_QUEUE
from scanner.api_engine import APIEngine
from core.job_tracker import update_stage

engine = APIEngine()


async def main():
    logging.info("[API WORKER] Ready and listening...")

    while True:
        job = pop(API_QUEUE)

        if not job:
            await asyncio.sleep(1)
            continue

        job_id     = job.get("job_id")
        target_url = job.get("url")
        auth_token = job.get("auth_token")   # optional Bearer token
        spec_url   = job.get("spec_url")     # optional OpenAPI spec URL

        try:
            logging.info(f"[API WORKER] Scanning: {target_url}")
            update_stage(job_id, "api_scan", 10)

            findings = await engine.scan(
                base_url=target_url,
                auth_token=auth_token,
                spec_url=spec_url
            )

            logging.info(f"[API WORKER] {len(findings)} findings for {target_url}")
            update_stage(job_id, "api_scan_done", 50)

            push(AGGREGATION_QUEUE, {
                "job_id":   job_id,
                "findings": findings
            })

        except Exception as e:
            logging.error(f"[API WORKER] Failed for {target_url}: {e}")
            retry(API_QUEUE, job, str(e))


asyncio.run(main())