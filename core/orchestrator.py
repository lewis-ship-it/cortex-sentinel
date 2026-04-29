# core/orchestrator.py
# ──────────────────────────────────────────────────────────────────────────────
# FIXES IN THIS VERSION
#
#   FIX 1 — handle_completion() was a redundant, conflicting routing layer
#     The old handle_completion() replicated the same push/status-update logic
#     that core/pipeline.py already handles correctly via on_crawl_complete(),
#     on_scan_complete(), etc.  crawl_worker called BOTH:
#       • orchestrator.handle_completion("crawl", ...)  → push to scan_queue
#       • core/pipeline.on_crawl_complete(...)           → push to scan_queue again
#     This caused every URL to be scanned twice.
#
#     handle_completion() has been removed.  All pipeline routing now goes
#     exclusively through core/pipeline.py.  crawl_worker was already fixed
#     to call on_crawl_complete() directly.
#
#   FIX 2 — db.update_job_status() in handle_completion() used force=True
#     which bypassed the state machine, producing invalid status transitions
#     visible in the dashboard (e.g. "done" jumping back to "scanning").
#     Removed entirely along with handle_completion().
#
#   RETAINED — stale job cleanup loop
#     cleanup_stale_jobs() / start_cleanup_loop() are still needed: they
#     recover jobs that were in-flight when a worker container crashed.
#     These are called from the API lifespan or a dedicated cron container.
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import logging

from core.database import get_db

logger = logging.getLogger(__name__)


class Orchestrator:

    def __init__(self):
        self.cleanup_interval = 900  # 15 minutes

    async def cleanup_stale_jobs(self, timeout_minutes: int = 30) -> int:
        """
        Mark jobs that have not been updated in `timeout_minutes` as failed.

        These are jobs whose worker process crashed without writing a terminal
        status.  Safe to call repeatedly — already-failed/done jobs are ignored
        by DatabaseManager.get_stale_jobs().

        Returns the number of jobs recovered.
        """
        db = get_db()
        recovered = db.recover_stale_jobs(timeout_minutes)
        if recovered > 0:
            logger.warning(f"[ORCH] Recovered {recovered} stale job(s)")
        return recovered

    async def start_cleanup_loop(self) -> None:
        """
        Background task that periodically cleans up stale jobs.
        Call once at application startup (e.g. from the FastAPI lifespan hook).
        """
        logger.info(
            f"[ORCH] Stale-job cleanup loop started "
            f"(interval={self.cleanup_interval}s, timeout=30min)"
        )
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup_stale_jobs()
            except asyncio.CancelledError:
                logger.info("[ORCH] Cleanup loop cancelled — shutting down")
                break
            except Exception as e:
                logger.error(f"[ORCH] Cleanup loop error: {e}")


# Module-level singleton
orchestrator = Orchestrator()