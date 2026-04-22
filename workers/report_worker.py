# workers/report_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# Uses AIReportGenerator (Ollama-backed). No external AI provider.
#
# FIXES vs previous version:
#   1. Key mismatch: old orchestrator.py pushed {"data": results} to REPORT_QUEUE
#      but this worker read job["findings"] — KeyError on every report job.
#      Fixed: read job.get("data") OR job.get("findings") with fallback.
#   2. Missing tier fallback to on_report_complete — tier now always propagated.
#   3. Added global exception handler so a bad report never kills the worker.
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import traceback

from workers.base_worker import worker_loop, push_log
from task_queue.queues import REPORT_QUEUE
from core.pipeline import on_report_complete
from core.database import get_db
from core.logger import get_logger
from scanner.ai_report import AIReportGenerator

logger   = get_logger("report_worker")
reporter = AIReportGenerator()


async def generate_tiered_report(job_id: str, data: dict, target: str, tier: str) -> dict:
    """Orchestrates AI report generation. Only Professional tier triggers AI."""
    if tier == "Basic":
        push_log(
            job_id,
            "[REPORT] Basic tier: skipping AI report, routing to Scorer.",
            tier=tier,
        )
        return {"error": "AI Report requires Professional tier."}

    push_log(job_id, f"[REPORT] AI Brain synthesizing report for {target}...", tier=tier)

    # Will raise httpx.ConnectError if Ollama is down — intentional hard failure.
    report = await reporter.generate_report(data, target, tier=tier)
    return report


def handle(job: dict) -> None:
    job_id = job["job_id"]
    tier   = job.get("tier", "Basic")
    target = job.get("target", "unknown")

    # FIX: old orchestrator pushed key "data", new pipeline uses "findings".
    # Support both keys so both code paths work.
    data = job.get("findings") or job.get("data") or {}

    # Normalise: if data arrived as a list (raw findings list), wrap it
    if isinstance(data, list):
        data = {"findings": data}

    try:
        push_log(job_id, f"[REPORT] Starting report generation ({tier})", tier=tier)
        report = asyncio.run(generate_tiered_report(job_id, data, target, tier))
        push_log(job_id, "[REPORT] Generation complete.", tier=tier)
        on_report_complete(job_id, report, tier=tier)

    except Exception as exc:
        tb = traceback.format_exc()
        logger.error(f"Report worker failed: {exc}\n{tb}", job_id)
        push_log(job_id, f"[ERROR] Report worker failed: {exc}", tier=tier)
        try:
            get_db().save_error_log(job_id, f"Report worker exception:\n{tb}")
        except Exception:
            pass
        # Fail gracefully — push an empty report so the job completes
        on_report_complete(job_id, {"error": str(exc), "findings": []}, tier=tier)


if __name__ == "__main__":
    worker_loop(REPORT_QUEUE, handle)