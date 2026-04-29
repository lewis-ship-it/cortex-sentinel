# core/job_tracker.py
# ──────────────────────────────────────────────────────────────────────────────
# FIX — Separate DatabaseManager instance created its own connection
#   Old code:  db = DatabaseManager()
#   This created a SECOND singleton alongside the one returned by get_db(),
#   so writes from job_tracker could target a different in-memory state and,
#   on some DB path configurations, a different file altogether.
#
#   Fixed: all calls now go through get_db() which returns the project-wide
#   singleton, guaranteeing all components read and write the same database.
# ──────────────────────────────────────────────────────────────────────────────

from core.database import get_db


def create_job(job_id: str, url: str) -> None:
    get_db().insert_job(job_id, url, status="pending", progress=0)


def get_job(job_id: str):
    return get_db().get_job(job_id)


def update_job(job_id: str, status: str = None, progress: int = None) -> None:
    get_db().update_job(job_id, status=status, progress=progress)


def update_stage(job_id: str, stage: str, progress: int) -> None:
    """Alias used by workers for stage-based progress updates."""
    get_db().update_job(job_id, status=stage, progress=progress)


def append_findings(job_id: str, findings: list) -> None:
    """Save raw vulnerability findings to the database."""
    get_db().save_vulnerabilities(job_id, findings)