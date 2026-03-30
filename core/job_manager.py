from core.database import DatabaseManager

db = DatabaseManager()

def create_job(job_id, url):
    db.insert_job(job_id, url, "queued", 0)

def update_job(job_id, status=None, progress=None):
    db.update_job(job_id, status, progress)

def get_job(job_id):
    return db.get_job(job_id)