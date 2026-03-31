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

    def save_vulnerabilities(self, job_id, results):
        if not results: return
        data = []
        for r in results:
            data.append({
                "job_id": job_id,
                "type": r.get("type"),
                "severity": r.get("severity"),
                "url": r.get("url"),
                "description": r.get("description", "Vulnerability detected by scanner")
            })
        self.db.table("vulnerabilities").insert(data).execute()

    def save_report(self, job_id, content):
        # Assumes you have a 'reports' table or a 'report' column in 'jobs'
        # Adjust table name if necessary
        self.db.table("reports").insert({
            "job_id": job_id,
            "content": content
        }).execute()

    def get_report(self, job_id):
        res = self.db.table("reports").select("*").eq("job_id", job_id).execute()
        return res.data[0] if res.data else None

    def get_results(self, job_id):
        res = self.db.table("vulnerabilities").select("*").eq("job_id", job_id).execute()
        return res.data