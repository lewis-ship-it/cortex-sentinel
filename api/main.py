# api/main.py

import threading
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from workers.workers import start_worker_loop
        worker_thread = threading.Thread(target=start_worker_loop, daemon=True)
        worker_thread.start()
        print("✅ Background Worker Thread Started Successfully")
    except Exception as e:
        print(f"❌ CRITICAL: Worker failed to start: {e}")
    yield
    print("🛠️  Worker Thread: Stopping...")


api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)
API_KEYS = {os.getenv("SENTINEL_API_KEY", "test-key-123")}


def verify_api_key(key: str = Security(api_key_header)):
    if key not in API_KEYS:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return key


app = FastAPI(
    title="Sentinel AI API",
    lifespan=lifespan,
    dependencies=[Depends(verify_api_key)]
)
db = DatabaseManager()


# ─────────────────────────────────────────────
# WEB APP SCAN
# ─────────────────────────────────────────────
@app.post("/scan")
async def scan(req: dict, key: str = Depends(verify_api_key)):
    target_url = req.get("url")
    user_id    = key

    if not target_url:
        raise HTTPException(400, "Missing URL")
    if not limiter.allow(user_id):
        raise HTTPException(429, "Too many requests")
    if not guard.is_allowed(target_url):
        raise HTTPException(403, "Target not allowed")
    if not req.get("verified", False):
        raise HTTPException(403, "Domain not verified")

    job_id = str(uuid.uuid4())
    create_job(job_id, target_url)
    enqueue_scan({"job_id": job_id, "url": target_url, "auth": req.get("auth")})

    return {"job_id": job_id, "type": "web_scan"}


# ─────────────────────────────────────────────
# NETWORK SCAN
# ─────────────────────────────────────────────
@app.post("/scan/network")
async def scan_network(req: dict, key: str = Depends(verify_api_key)):
    """
    Body:
    {
        "host":       "192.168.1.1",
        "port_range": [22, 80, 443],   # optional
        "verified":   true
    }
    """
    host    = req.get("host") or req.get("url")
    user_id = key

    if not host:
        raise HTTPException(400, "Missing host")
    if not limiter.allow(user_id):
        raise HTTPException(429, "Too many requests")
    if not req.get("verified", False):
        raise HTTPException(403, "You must confirm you have permission to scan this host")

    job_id = str(uuid.uuid4())
    create_job(job_id, host)
    push(NETWORK_QUEUE, {
        "job_id":     job_id,
        "url":        host,
        "port_range": req.get("port_range", None)
    })

    return {"job_id": job_id, "type": "network_scan"}


# ─────────────────────────────────────────────
# API DEEP SCAN  ← new
# ─────────────────────────────────────────────
@app.post("/scan/api")
async def scan_api(req: dict, key: str = Depends(verify_api_key)):
    """
    Deep API security scan: GraphQL, JWT, BOLA, rate limiting,
    mass assignment, CORS, HTTP method abuse, and more.

    Body:
    {
        "url":        "https://api.example.com",   # required
        "auth_token": "eyJ...",                    # optional Bearer token
        "spec_url":   "https://api.example.com/openapi.json",  # optional
        "verified":   true
    }
    """
    target_url = req.get("url")
    user_id    = key

    if not target_url:
        raise HTTPException(400, "Missing URL")
    if not limiter.allow(user_id):
        raise HTTPException(429, "Too many requests")
    if not guard.is_allowed(target_url):
        raise HTTPException(403, "Target not allowed")
    if not req.get("verified", False):
        raise HTTPException(403, "You must confirm you have permission to scan this API")

    job_id = str(uuid.uuid4())
    create_job(job_id, target_url)
    push(API_QUEUE, {
        "job_id":     job_id,
        "url":        target_url,
        "auth_token": req.get("auth_token"),
        "spec_url":   req.get("spec_url"),
    })

    return {"job_id": job_id, "type": "api_scan"}


# ─────────────────────────────────────────────
# STATUS / RESULTS
# ─────────────────────────────────────────────
@app.get("/job/{job_id}")
def job_status(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
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
    builder.build_pdf(file_path, report["content"])
    return {"file": file_path}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("api.main:app", host="0.0.0.0", port=port, reload=False)