from fastapi import FastAPI, Request, Security, HTTPException, Depends
from fastapi.security.api_key import APIKeyHeader
import uuid
import os
from dotenv import load_dotenv

from task_queue.redis_scanner import enqueue_scan
from core.job_manager import create_job, get_job
from core.database import DatabaseManager

load_dotenv()

# 1. Security Setup for Swagger UI
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)
API_KEYS = {os.getenv("SENTINEL_API_KEY", "test-key-123")}

def verify_api_key(key: str = Security(api_key_header)):
    if key not in API_KEYS:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return key

app = FastAPI(dependencies=[Depends(verify_api_key)])
db = DatabaseManager()

@app.post("/scan")
def scan(req: dict):
    target_url = req.get("url")
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing url")
        
    job_id = str(uuid.uuid4())
    
    try:
        # Create job entry in the database
        create_job(job_id, target_url)
        
        # Queue the job for the worker
        enqueue_scan({
            "job_id": job_id,
            "url": target_url,
            "auth": req.get("auth")
        })
        
        return {"job_id": job_id}
    except Exception as e:
        print(f"DATABASE ERROR: {e}")
        raise HTTPException(status_code=500, detail="RLS or Database Error")

@app.get("/job/{job_id}")
def job_status(job_id: str):
    return get_job(job_id)

@app.get("/result/{job_id}")
def result(job_id: str):
    # Searches by the UUID job_id
    vulns = db.get_results(job_id)
    if not vulns:
        return {"status": "not_found", "vulnerabilities": []}
    return {"status": "done", "vulnerabilities": vulns}

# 🔥 NEW ENDPOINT ADDED
@app.get("/report/{job_id}")
def get_report(job_id: str):
    """
    Fetches the full security report for a specific job ID, 
    including severity scores and summarized findings.
    """
    report = db.get_report(job_id)
    if not report:
         raise HTTPException(status_code=404, detail="Report not found")
    return report