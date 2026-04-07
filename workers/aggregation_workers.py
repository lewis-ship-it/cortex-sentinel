# workers/aggregation_workers.py

import asyncio
import logging
import time

from task_queue.redis_client import pop, push, retry
from task_queue.queues import AGGREGATION_QUEUE, REPORT_QUEUE
from core.aggregation_store import add_findings, get_findings
from core.job_tracker import update_stage

# Trigger report after this many batches received
BATCH_THRESHOLD = 5

# OR trigger report after this many seconds since first batch (safety net)
TIME_THRESHOLD_SECONDS = 120

job_counter    = {}
job_first_seen = {}


async def main():
    while True:
        job = pop(AGGREGATION_QUEUE)

        if not job:
            await asyncio.sleep(1)

            # Time-based fallback: flush jobs that have been waiting too long
            now = time.time()
            for job_id, first_seen in list(job_first_seen.items()):
                if now - first_seen > TIME_THRESHOLD_SECONDS:
                    all_findings = get_findings(job_id)
                    if all_findings:
                        push(REPORT_QUEUE, {
                            "job_id":   job_id,
                            "findings": all_findings
                        })
                        logging.info(f"[AGG] Time-based flush for {job_id}")
                    del job_counter[job_id]
                    del job_first_seen[job_id]

            continue

        try:
            job_id   = job["job_id"]
            findings = job.get("findings", [])

            add_findings(job_id, findings)

            job_counter[job_id] = job_counter.get(job_id, 0) + 1

            # Track first time we saw this job
            if job_id not in job_first_seen:
                job_first_seen[job_id] = time.time()

            logging.info(f"[AGG] Job {job_id} batch #{job_counter[job_id]}")
            update_stage(job_id, "aggregating", 80)

            if job_counter[job_id] >= BATCH_THRESHOLD:
                all_findings = get_findings(job_id)

                push(REPORT_QUEUE, {
                    "job_id":   job_id,
                    "findings": all_findings
                })

                logging.info(f"[AGG] Triggering report for {job_id}")

                del job_counter[job_id]
                del job_first_seen[job_id]

        except Exception as e:
            retry(AGGREGATION_QUEUE, job, str(e))


asyncio.run(main())