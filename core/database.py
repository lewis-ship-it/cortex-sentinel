import os
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()

class DatabaseManager:
    def __init__(self):
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY")
        if not url or not key:
            raise Exception("Missing Supabase credentials")
        self.db = create_client(url, key)

    # -----------------------
    # JOB MANAGEMENT
    # -----------------------
    def insert_job(self, job_id, url, status, progress):
        self.db.table("jobs").insert({
            "id": job_id,
            "url": url,
            "status": status,
            "progress": progress
        }).execute()

    def update_job(self, job_id, status=None, progress=None):
        update_data = {}
        if status:
            update_data["status"] = status
        if progress is not None:
            update_data["progress"] = progress

        if update_data:
            self.db.table("jobs").update(update_data).eq("id", job_id).execute()

    def get_job(self, job_id):
        res = self.db.table("jobs").select("*").eq("id", job_id).execute()
        return res.data[0] if res.data else None

    # -----------------------
    # VULNERABILITIES
    # -----------------------
    def save_vulnerabilities(self, job_id, results):
        if not results:
            return

        data = []
        for r in results:
            data.append({
                "job_id": job_id,
                "type": r.get("type"),
                "severity": r.get("severity"),
                "url": r.get("url"),
                "description": r.get("description", ""),
                "payload": r.get("payload")
            })

        self.db.table("vulnerabilities").insert(data).execute()

    def get_results(self, job_id):
        res = self.db.table("vulnerabilities").select("*").eq("job_id", job_id).execute()
        return res.data

    # -----------------------
    # REPORTS
    # -----------------------
    def save_report(self, job_id, content):
        self.db.table("reports").insert({
            "job_id": job_id,
            "content": content
        }).execute()

    def get_report(self, job_id):
        res = self.db.table("reports").select("*").eq("job_id", job_id).execute()
        return res.data[0] if res.data else None