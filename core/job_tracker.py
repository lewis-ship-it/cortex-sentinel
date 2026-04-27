
# core/job_tracker.py
from core.database import DatabaseManager

db = DatabaseManager()


def create_job(job_id: str, url: str):
    db.insert_job(job_id, url, status="pending", progress=0)


def get_job(job_id: str):
    return db.get_job(job_id)


def update_job(job_id: str, status: str = None, progress: int = None):
    db.update_job(job_id, status=status, progress=progress)


def update_stage(job_id: str, stage: str, progress: int):
    """Alias used by workers for stage-based progress updates."""
    db.update_job(job_id, status=stage, progress=progress)


def append_findings(job_id: str, findings: list):
    """Save raw vulnerability findings to the database."""
    db.save_vulnerabilities(job_id, findings)

