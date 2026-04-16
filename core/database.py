import os
import logging
from supabase import create_client
from dotenv import load_dotenv

# Initialize logging to see errors in Docker logs
load_dotenv()
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY")
        
        # Guard against missing credentials to prevent 'AttributeError'
        if not url or not key:
            logger.warning("[DB] SUPABASE_URL or KEY missing. Database features disabled.")
            self.db = None
            return
            
        try:
            self.db = create_client(url, key)
            logger.info("[DB] Supabase connected successfully.")
        except Exception as e:
            logger.error(f"[DB] Connection failed: {e}")
            self.db = None

    # --- Job Management ---
    
    def insert_job(self, job_id, url, status="pending", progress=0):
        """
        Inserts a new scan job. 
        Note: status and progress now have default values to prevent TypeErrors.
        """
        if not self.db: return
        
        try:
            return self.db.table("jobs").insert({
                "id": job_id,
                "target_url": url,  # Matches your Supabase column name
                "status": status,
                "progress": progress
            }).execute()
        except Exception as e:
            logger.error(f"[DB] insert_job error: {e}")

    def update_job(self, job_id, status=None, progress=None):
        if not self.db: return
        
        update_data = {}
        if status is not None: update_data["status"] = status
        if progress is not None: update_data["progress"] = progress
        
        try:
            if update_data:
                return self.db.table("jobs").update(update_data).eq("id", job_id).execute()
        except Exception as e:
            logger.error(f"[DB] update_job error: {e}")

    # --- Findings & Reports ---

    def save_vulnerabilities(self, job_id, results):
        """Maps 'url' from scanner results to 'target_url' in database."""
        if not self.db or not results: return
        
        try:
            data = []
            for r in results:
                data.append({
                    "job_id": job_id,
                    "type": r.get("type"),
                    "severity": r.get("severity"),
                    "target_url": r.get("url") or r.get("target_url"), # Mapping fix
                    "description": r.get("description", ""),
                    "payload": r.get("payload")
                })
            return self.db.table("vulnerabilities").insert(data).execute()
        except Exception as e:
            logger.error(f"[DB] save_vulnerabilities error: {e}")

    def save_report(self, job_id, content):
        if not self.db: return
        try:
            return self.db.table("reports").insert({
                "job_id": job_id, 
                "content": content
            }).execute()
        except Exception as e:
            logger.error(f"[DB] save_report error: {e}")

    # --- Logging ---

    def add_log(self, job_id, message):
        if not self.db: return
        try:
            self.db.table("scan_logs").insert({
                "job_id": job_id, 
                "message": message
            }).execute()
        except Exception:
            pass # Keep worker running even if logging fails

    def get_logs(self, job_id):
        if not self.db: return []
        try:
            res = self.db.table("scan_logs").select("*").eq("job_id", job_id).order("created_at").execute()
            return res.data
        except Exception:
            return []