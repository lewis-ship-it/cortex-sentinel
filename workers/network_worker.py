# workers/network_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# FIX — CPU-spinning busy-loop
#   Old code used non-blocking pop() + asyncio.sleep(1) in the main loop.
#   Fixed: replaced with blocking_pop(timeout=5) to eliminate idle CPU burn.
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import logging

from task_queue.redis_client import blocking_pop, push, retry_job as retry
from task_queue.queues import NETWORK_QUEUE, AGGREGATION_QUEUE
from scanner.network_engine import NetworkEngine
from core.job_tracker import update_stage

engine = NetworkEngine()


async def main() -> None:
    logging.info("[NET WORKER] Ready and listening...")
    while True:
        # FIX: blocking_pop replaces pop() + asyncio.sleep(1) busy-loop
        job = blocking_pop(NETWORK_QUEUE, timeout=5)
        if not job:
            continue

        job_id = job.get("job_id")
        target = job.get("url") or job.get("host")

        try:
            logging.info(f"[NET WORKER] Scanning: {target}")
            update_stage(job_id, "network_scan", 15)

            findings = await engine.scan(target, port_range=job.get("port_range"))

            logging.info(f"[NET WORKER] {len(findings)} findings for {target}")
            update_stage(job_id, "network_scan_done", 40)

            push(AGGREGATION_QUEUE, {"job_id": job_id, "findings": findings})

        except Exception as e:
            logging.error(f"[NET WORKER] Failed for {target}: {e}")
            retry(NETWORK_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())