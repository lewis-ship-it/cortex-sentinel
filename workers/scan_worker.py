# workers/scan_worker.py
#
# PLACEMENT: Replace workers/scan_worker.py entirely.
#
# WHAT CHANGED:
#   • Calls filter_false_positives() after every scan
#   • Updates job status in DB during the scan lifecycle
#   • WAF name forwarded to findings metadata

import asyncio
import logging

from task_queue.redis_client import pop, retry
from task_queue.queues import SCAN_QUEUE
from scanner.dast.active_scanner import ActiveScanner, filter_false_positives
from scanner.ai_brain import AIBrain
from core.orchestrator import Orchestrator
from core.job_tracker import update_stage

logger       = logging.getLogger(__name__)
scanner      = ActiveScanner()
brain        = AIBrain()
orchestrator = Orchestrator()


async def main():
    logging.basicConfig(level=logging.INFO)
    logger.info("[SCAN WORKER] Ready and listening...")

    while True:
        job = pop(SCAN_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue

        job_id = job.get("job_id")
        url    = job.get("url")
        auth   = job.get("auth")

        try:
            logger.info(f"[SCAN WORKER] Starting: {url}")
            update_stage(job_id, "scanning", 10)

            # ── Run the full scan ──────────────────────────────────────────────
            raw_findings = await scanner.scan(url, auth_config=auth)
            logger.info(f"[SCAN WORKER] Raw findings: {len(raw_findings)}")

            update_stage(job_id, "validating", 70)

            # ── AI false-positive filter ───────────────────────────────────────
            # This removes noise before the report is generated.
            # Findings with AI confidence < 0.6 are dropped.
            validated = await filter_false_positives(raw_findings, brain)
            logger.info(
                f"[SCAN WORKER] After AI filter: {len(validated)} "
                f"(dropped {len(raw_findings) - len(validated)} false positives)"
            )

            update_stage(job_id, "scan_done", 90)

            # ── Forward to orchestrator ────────────────────────────────────────
            await orchestrator.on_stage_complete(
                job_id, "scan", {"findings": validated}
            )

        except Exception as e:
            logger.error(f"[SCAN WORKER] Error for {url}: {e}", exc_info=True)
            retry(SCAN_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())
