# workers/network_worker.py

import asyncio
import logging

from task_queue.redis_client import pop, push, retry
from task_queue.queues import NETWORK_QUEUE, AGGREGATION_QUEUE
from scanner.network_engine import NetworkEngine
from core.job_tracker import update_stage

engine = NetworkEngine()


async def main():
    logging.info("[NET WORKER] Ready and listening...")

    while True:
        job = pop(NETWORK_QUEUE)

        if not job:
            await asyncio.sleep(1)
            continue

        job_id = job.get("job_id")
        target  = job.get("url") or job.get("host")

        try:
            logging.info(f"[NET WORKER] Scanning: {target}")
            update_stage(job_id, "network_scan", 15)

            port_range = job.get("port_range", None)  # optional override
            findings = await engine.scan(target, port_range=port_range)

            logging.info(f"[NET WORKER] {len(findings)} findings for {target}")
            update_stage(job_id, "network_scan_done", 40)

            push(AGGREGATION_QUEUE, {
                "job_id":   job_id,
                "findings": findings
            })

        except Exception as e:
            logging.error(f"[NET WORKER] Failed for {target}: {e}")
            retry(NETWORK_QUEUE, job, str(e))


asyncio.run(main())