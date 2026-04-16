import os
from supabase import create_client

class DatabaseManager:
    def __init__(self):
        self.url = os.getenv("SUPABASE_URL")
        self.key = os.getenv("SUPABASE_KEY")
        if not self.url or not self.key:
            self.db = None
            return
        try:
            self.db = create_client(self.url, self.key)
        except Exception:
            self.db = None

    def insert_job(self, job_id, url, status, progress):
        """Ensures the key is 'target_url' to match Supabase."""
        if not self.db: return
        return self.db.table("jobs").insert({
            "id": job_id,
            "target_url": url,  # Matches your DB column name
            "status": status,
            "progress": progress
        }).execute()

    def save_vulnerabilities(self, job_id, results):
        """Standardizes vulnerability storage."""
        if not self.db or not results: return
        data = []
        for r in results:
            data.append({
                "job_id": job_id,
                "type": r.get("type"),
                "severity": r.get("severity"),
                "target_url": r.get("url") or r.get("target_url"), # Fix here
                "description": r.get("description", ""),
                "payload": r.get("payload")
            })
        return self.db.table("vulnerabilities").insert(data).execute()