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

    # JOBS
    def insert_job(self, job_id, url, status, progress):
        self.db.table("jobs").insert({
            "id": job_id,
            "url": url,
            "status": status,
            "progress": progress
        }).execute()

    def update_job(self, job_id, status=None, progress=None):
        data = {}
        if status: data["status"] = status
        if progress is not None: data["progress"] = progress

        self.db.table("jobs").update(data).eq("id", job_id).execute()

    def get_job(self, job_id):
        res = self.db.table("jobs").select("*").eq("id", job_id).execute()
        return res.data[0] if res.data else None

    # RESULTS
    def save_vulnerabilities(self, job_id, vulns):
        for v in vulns:
            self.db.table("vulnerabilities").insert({
                "job_id": job_id,
                "type": v["type"],
                "severity": v["severity"],
                "endpoint": v.get("url"),
                "payload": v.get("payload")
            }).execute()

    def get_results(self, job_id):
        res = self.db.table("vulnerabilities").select("*").eq("job_id", job_id).execute()
        return res.data