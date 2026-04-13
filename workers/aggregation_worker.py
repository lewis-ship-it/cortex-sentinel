# workers/aggregation_worker.py
import asyncio, logging, time
from task_queue.redis_client import pop, push, retry
from task_queue.queues import AGGREGATION_QUEUE, REPORT_QUEUE
from storage.aggregation_store import add_findings, get_findings
from core.orchestrator import Orchestrator

logger = logging.getLogger(__name__)
orchestrator = Orchestrator()

# Trigger report after this many scan batches OR this many seconds
BATCH_THRESHOLD        = 5
TIME_THRESHOLD_SECONDS = 90

job_counter    = {}
job_first_seen = {}


async def main():
    logging.basicConfig(level=logging.INFO)
    logger.info("[AGG WORKER] Ready...")
    while True:
        job = pop(AGGREGATION_QUEUE)
        if not job:
            await asyncio.sleep(1)
            # Time-based flush
            now = time.time()
            for jid, first in list(job_first_seen.items()):
                if now - first > TIME_THRESHOLD_SECONDS:
                    all_f = get_findings(jid)
                    if all_f:
                        push(REPORT_QUEUE, {"job_id": jid, "findings": all_f})
                        logger.info(f"[AGG] Time-flush for {jid}")
                    job_counter.pop(jid, None)
                    job_first_seen.pop(jid, None)
            continue

        try:
            job_id   = job["job_id"]
            findings = job.get("data", {}).get("findings", [])
            add_findings(job_id, findings)
            job_counter[job_id]    = job_counter.get(job_id, 0) + 1
            job_first_seen.setdefault(job_id, time.time())
            logger.info(f"[AGG] Job {job_id} batch #{job_counter[job_id]}")
            await orchestrator.on_stage_complete(job_id, "aggregation",
                                                 {"findings": get_findings(job_id)})
            if job_counter[job_id] >= BATCH_THRESHOLD:
                all_f = get_findings(job_id)
                push(REPORT_QUEUE, {"job_id": job_id, "findings": all_f})
                job_counter.pop(job_id, None)
                job_first_seen.pop(job_id, None)
        except Exception as e:
            retry(AGGREGATION_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())
