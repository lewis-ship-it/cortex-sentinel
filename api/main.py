# api/main.py
#
# FIX 1: verify_api_key was defined before db was created.
#         Moved db instantiation before the function that uses it.
# FIX 2: Uses core/database.py (self.db) consistently.

import uuid
import os
import uvicorn
from fastapi import FastAPI, Security, HTTPException, Depends
from fastapi.security.api_key import APIKeyHeader
from contextlib import asynccontextmanager
from dotenv import load_dotenv

from task_queue.redis_scanner import enqueue_scan
from task_queue.redis_client import push
from task_queue.queues import NETWORK_QUEUE, MOBILE_QUEUE, API_QUEUE
from core.job_tracker import create_job, get_job
from core.database import DatabaseManager
from scanner.report_builder import ReportBuilder
from scanner.safety_guard import SafetyGuard
from api.domain_verification import DomainVerifier
from scanner.rate_limiter import RateLimiter

load_dotenv()

builder  = ReportBuilder()
guard    = SafetyGuard()
verifier = DomainVerifier()
limiter  = RateLimiter()

# FIX: db must be created BEFORE verify_api_key uses it
db = DatabaseManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Sentinel API Online")
    yield
    print("🛑 Sentinel API Shutting down")

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

# FIX: Now defined after db — no NameError
def verify_api_key(key: str = Security(api_key_header)):
    if not key:
        raise HTTPException(status_code=403, detail="API key required")
    # Check key against Supabase users table (gracefully skips if DB is down)
    if db.db:
        try:
            res = db.db.table("users").select("api_key").eq("api_key", key).execute()
            if res.data:  # Only reject if we found data and it doesn't match
                return key
        except Exception:
            # If DB lookup fails, fall back to env-based key check
            pass
    
    # Fallback: env-configured key
    env_key = os.getenv("SENTINEL_API_KEY", "test-key-123")
    if key != env_key:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return key


app = FastAPI(
    title="Sentinel AI API",
    lifespan=lifespan,
)


@app.post("/scan")
async def scan(req: dict, key: str = Depends(verify_api_key)):
    target_url = req.get("url")
    if not target_url:
        raise HTTPException(400, "Missing URL")
    if not limiter.allow(key):
        raise HTTPException(429, "Too many requests")
    if not guard.is_allowed(target_url):
        raise HTTPException(403, "Target not allowed")

    token = req.get("verification_token")
    if token:
        verified = await verifier.verify_domain(target_url, token)
        if not verified:
            raise HTTPException(403, "Domain verification failed")

    job_id = str(uuid.uuid4())
    create_job(job_id, target_url)
    enqueue_scan({"job_id": job_id, "target_url": target_url, "auth": req.get("auth")})
    return {"job_id": job_id, "type": "web_scan"}


@app.post("/scan/network")
async def scan_network(req: dict, key: str = Depends(verify_api_key)):
    host = req.get("host") or req.get("url")
    if not host:
        raise HTTPException(400, "Missing host")
    if not limiter.allow(key):
        raise HTTPException(429, "Too many requests")
    if not req.get("verified", False):
        raise HTTPException(403, "Permission confirmation required")
    job_id = str(uuid.uuid4())
    create_job(job_id, host)
    push(NETWORK_QUEUE, {"job_id": job_id, "url": host, "port_range": req.get("port_range")})
    return {"job_id": job_id, "type": "network_scan"}


@app.post("/scan/api")
async def scan_api(req: dict, key: str = Depends(verify_api_key)):
    target_url = req.get("url")
    if not target_url:
        raise HTTPException(400, "Missing URL")
    if not limiter.allow(key):
        raise HTTPException(429, "Too many requests")
    if not guard.is_allowed(target_url):
        raise HTTPException(403, "Target not allowed")
    if not req.get("verified", False):
        raise HTTPException(403, "Permission confirmation required")
    job_id = str(uuid.uuid4())
    create_job(job_id, target_url)
    push(API_QUEUE, {
        "job_id": job_id, "url": target_url,
        "auth_token": req.get("auth_token"), "spec_url": req.get("spec_url"),
    })
    return {"job_id": job_id, "type": "api_scan"}


@app.get("/job/{job_id}")
def job_status(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@app.get("/logs/{job_id}")
def get_logs(job_id: str):
    return db.get_logs(job_id)


@app.get("/report/pdf/{job_id}")
def generate_pdf(job_id: str):
    report = db.get_report(job_id)
    if not report:
        raise HTTPException(404, "Report not found")
    file_path = f"report_{job_id}.pdf"
    builder.build_pdf(file_path, report.get("content", report))
    return {"file": file_path}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("api.main:app", host="0.0.0.0", port=port, reload=False)
