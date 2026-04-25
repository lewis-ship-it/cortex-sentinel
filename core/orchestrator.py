# core/orchestrator.py
#
# FIX: Imports core/database.py (which has self.db) not storage/database.py
#      (which had self.client). The two had incompatible attributes causing
#      AttributeError on every db call.
# FIX: Added stale job cleanup mechanism for crash recovery

import logging
import asyncio
from task_queue.redis_client import push, log_event
from task_queue.queues import SCAN_QUEUE, EXPLOIT_QUEUE, REPORT_QUEUE
from core.database import DatabaseManager

logger = logging.getLogger(__name__)
db = DatabaseManager()


class Orchestrator:
    def __init__(self):
        self.stages = ["crawl", "scan", "exploit", "report"]
        self.cleanup_interval = 900  # 15 minutes

    async def handle_completion(self, job_id: str, current_stage: str, results: dict):
        try:
            log_event(job_id, "ORCH", f"Handling completion for stage: {current_stage}")

            # ------------------ CRAWL → SCAN ------------------
            if current_stage == "crawl":
                urls = results.get("urls", [])

                if not urls:
                    self._fail_job(job_id, "No URLs discovered during crawl.")
                    return

                db.init_job_counter(job_id, len(urls))
                db.update_job_status(job_id, "scanning", 25)

                log_event(job_id, "ORCH", f"Crawl done. {len(urls)} URLs → Scan queue")

                for url in set(urls):
                    push(SCAN_QUEUE, {
                        "job_id": job_id,
                        "url": url,
                        "target_url": url
                    })

            # ------------------ SCAN → EXPLOIT ------------------
            elif current_stage == "scan":
                remaining = db.decrement_pending_scans(job_id)

                log_event(job_id, "ORCH", f"Scan task done. Remaining: {remaining}")

                if remaining > 0:
                    return

                findings = results.get("极findings", [])

                if not findings:
                    log_event(job_id, "ORCH", "No vulnerabilities found. Completing job.")
                    db.update_job_status(job_id, "completed", 100)
                    return

                db.update_job_status(job_id, "exploiting", 60)

                push(EXPLOIT_QUEUE, {
                    "job_id": job_id,
                    "findings": findings
                })

            # ------------------ EXPLOIT → REPORT ------------------
            elif current_stage == "exploit":
                db.update_job_status(job_id, "reporting", 90)

                push(REPORT_QUEUE, {
                    "job_id": job_id,
                    "data": results
                })

        except Exception as e:
            log_event(job_id, "ERROR", f"Orchestrator failure: {str(e)}")
            self._fail_job(job_id, str(e))

    def _fail_job(self, job_id: str, reason: str):
        log_event(job_id, "ERROR", reason)
        db.update_job_status(job_id, "failed", 100)

    async def cleanup_stale_jobs(self, timeout_minutes: int = 30):
        """
        Periodically check for and recover stale jobs.
        Call this in a background task or separate cleanup worker.

        Args:
            timeout_minutes: Jobs not updated in this many minutes are considered stale
        """
        recovered = db.recover_stale_jobs(timeout_minutes)
        if recovered > 0:
            logger.warning(f"[ORCH] Recovered {recovered} stale jobs")
        return recovered

    async def start_cleanup_loop(self):
        """
        Start a background task that periodically cleans up stale jobs.
        Call this once at application startup.
        """
        logger.info(f"[ORCH] Starting stale job cleanup loop (every {self.cleanup_interval}s)")
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup_stale_jobs()
            except Exception as e:
                logger.error(f"[ORCH] Cleanup loop error: {e}")


# ✅ global instance
orchestrator = Orchestrator()


# ✅ SAFE WRAPPER (THIS IS WHAT YOUR WORKERS SHOULD CALL)
def handle_stage_completion(job_id: str, stage: str, results: dict):
    asyncio.create_task(orchestrator.handle_completion(job_id, stage, results))
