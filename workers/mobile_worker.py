# workers/mobile_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# FIX — CPU-spinning busy-loop
#   Old code used non-blocking pop() + asyncio.sleep(1) in the main loop.
#   Fixed: replaced with blocking_pop(timeout=5) to eliminate idle CPU burn.
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import logging
import os

from task_queue.redis_client import blocking_pop, push, retry_job as retry
from task_queue.queues import MOBILE_QUEUE, AGGREGATION_QUEUE
from scanner.mobile.mobile_engine import MobileEngine
from core.job_tracker import update_stage

engine = MobileEngine()


async def main() -> None:
    logging.info("[MOBILE WORKER] Ready and listening...")
    while True:
        # FIX: blocking_pop replaces pop() + asyncio.sleep(1) busy-loop
        job = blocking_pop(MOBILE_QUEUE, timeout=5)
        if not job:
            continue

        job_id   = job.get("job_id")
        apk_path = job.get("apk_path")

        try:
            if not apk_path or not os.path.exists(apk_path):
                raise FileNotFoundError(f"APK not found: {apk_path}")

            logging.info(f"[MOBILE WORKER] Scanning: {apk_path}")
            update_stage(job_id, "mobile_scan", 10)

            loop     = asyncio.get_running_loop()
            findings = await loop.run_in_executor(None, engine.scan, apk_path)

            logging.info(f"[MOBILE WORKER] {len(findings)} findings for {apk_path}")
            update_stage(job_id, "mobile_scan_done", 50)

            push(AGGREGATION_QUEUE, {"job_id": job_id, "findings": findings})

        except Exception as e:
            logging.error(f"[MOBILE WORKER] Failed: {e}")
            retry(MOBILE_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())