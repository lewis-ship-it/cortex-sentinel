from core.database import DatabaseManager

db = DatabaseManager()


def create_job(job_id, url):
    """Create a new job record in the database."""
    db.insert_job(job_id, url, status="pending", progress=0)


def get_job(job_id):
    """Retrieve a job record by ID."""
    return db.get_job(job_id)


def update_job(job_id, status=None, progress=None):
    """Update job status and/or progress."""
    db.update_job(job_id, status=status, progress=progress)


def update_stage(job_id, stage, progress):
    """Alias used by worker modules for stage-based progress updates."""
    db.update_job(job_id, status=stage, progress=progress)


def append_findings(job_id, findings):
    # FIX: added "payload" field to match the vulnerabilities table schema
    if not findings:
        return
    data = []
    for f in findings:
        data.append({
            "job_id":      job_id,
            "type":        f.get("type"),
            "severity":    f.get("severity"),
            "url":         f.get("url"),
            "description": f.get("description", ""),
            "payload":     f.get("payload"),
        })
    db.db.table("vulnerabilities").insert(data).execute()
