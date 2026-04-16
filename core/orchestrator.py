# core/orchestrator.py
#
# FIX: Imports core/database.py (which has self.db) not storage/database.py
#      (which had self.client). The two had incompatible attributes causing
#      AttributeError on every db call.

import logging
from task_queue.redis_client import push, log_event
from task_queue.queues import SCAN_QUEUE, EXPLOIT_QUEUE, REPORT_QUEUE
from core.database import DatabaseManager

logger = logging.getLogger(__name__)
db = DatabaseManager()


class Orchestrator:
    def __init__(self):
        self.stages = ["crawl", "scan", "exploit", "report"]

    async def handle_completion(self, job_id: str, current_stage: str, results: dict):
        if current_stage == "crawl":
            urls = results.get("urls", [])
            if not urls:
                self._fail_job(job_id, "No URLs discovered during crawl.")
                return
            log_event(job_id, "ORCH", f"Crawl done. {len(urls)} targets → Scan queue.")
            db.update_job_status(job_id, "scanning", 25)
            for url in set(urls):
                push(SCAN_QUEUE, {"job_id": job_id, "url": url})

        elif current_stage == "scan":
            findings = results.get("findings", [])
            if not findings:
                log_event(job_id, "ORCH", "Scan complete. No vulnerabilities found.")
                db.update_job_status(job_id, "done", 100)
                return
            log_event(job_id, "ORCH", f"Scan complete. {len(findings)} vulns → Exploit.")
            db.update_job_status(job_id, "exploiting", 60)
            push(EXPLOIT_QUEUE, {"job_id": job_id, "findings": findings})

        elif current_stage == "exploit":
            db.update_job_status(job_id, "reporting", 90)
            push(REPORT_QUEUE, {"job_id": job_id, "data": results})

    def _fail_job(self, job_id: str, reason: str):
        log_event(job_id, "ERROR", reason)
        db.update_job_status(job_id, "failed", 100)


orchestrator = Orchestrator()
