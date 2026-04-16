# workers/mobile_worker.py

import asyncio
import logging
import os

from task_queue.redis_client import pop, push, retry
from task_queue.queues import MOBILE_QUEUE, AGGREGATION_QUEUE
from scanner.mobile_engine import MobileEngine
from core.job_tracker import update_stage

engine = MobileEngine()


async def main():
    logging.info("[MOBILE WORKER] Ready and listening...")
    while True:
        job = pop(MOBILE_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue

        job_id   = job.get("job_id")
        apk_path = job.get("apk_path")

        try:
            if not apk_path or not os.path.exists(apk_path):
                raise FileNotFoundError(f"APK not found at path: {apk_path}")

            logging.info(f"[MOBILE WORKER] Scanning: {apk_path}")
            update_stage(job_id, "mobile_scan", 10)

            loop     = asyncio.get_running_loop()  # FIX: get_event_loop() deprecated in 3.10+
            findings = await loop.run_in_executor(None, engine.scan, apk_path)

            logging.info(f"[MOBILE WORKER] {len(findings)} findings for {apk_path}")
            update_stage(job_id, "mobile_scan_done", 50)

            push(AGGREGATION_QUEUE, {"job_id": job_id, "findings": findings})

        except Exception as e:
            logging.error(f"[MOBILE WORKER] Failed: {e}")
            retry(MOBILE_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())
