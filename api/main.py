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
from task_queue.queues import NETWORK_QUEUE, MOBILE_QUEUE, API_QUEUE, SCAN_QUEUE
from core.job_tracker import create_job, get_job
from storage.database import DatabaseManager
from scanner.report_builder import ReportBuilder
from scanner.safety_guard import SafetyGuard
from api.domain_verification import DomainVerifier
from scanner.dast.rate_limiter import RateLimiter

load_dotenv()

builder = ReportBuilder()
guard = SafetyGuard()
verifier = DomainVerifier()
limiter = RateLimiter()

# FIX: detect Docker by checking for the container sentinel env var or hostname
# Only start an inline worker thread when running locally (not in Docker),
# since the Docker Compose stack runs the worker as its own dedicated service.
_IS_DOCKER = os.path.exists("/.dockerenv") or os.getenv("RUNNING_IN_DOCKER") == "1"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    API Lifecycle Manager.
    Note: We no longer start an internal worker thread here.
    The Scanner and Aggregator are now run as independent processes.
    """
    print("🚀 Cortex Sentinel API: Online")
    # You can initialize database connections here if needed
    yield
    print("🛠️  Cortex Sentinel API: Shutting down...")


api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)
API_KEYS = {os.getenv("SENTINEL_API_KEY", "test-key-123")}


def verify_api_key(key: str = Security(api_key_header)):
    if key not in API_KEYS:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return key


app = FastAPI(
    title="Sentinel AI API",
    lifespan=lifespan,
    dependencies=[Depends(verify_api_key)],
)
db = DatabaseManager()


@app.post("/scan")
async def scan(req: dict, key: str = Depends(verify_api_key)):
    target_url = req.get("url")
    user_id = key

    # 1. Safety Guards (All pass or raise Exception)
    if not target_url:
        raise HTTPException(400, "Missing URL")
    if not limiter.allow(user_id):
        raise HTTPException(429, "Too many requests")
    if not guard.is_allowed(target_url):
        raise HTTPException(403, "Target not allowed")
    if not req.get("verified", False):
        raise HTTPException(403, "Domain not verified")

    # 2. JOB EXECUTION (Must be at this indentation level)
    job_id = str(uuid.uuid4())
    create_job(job_id, target_url)

    from task_queue.queues import SCAN_QUEUE
    push(SCAN_QUEUE, {
        "job_id": job_id,
        "url": target_url,
        "auth": req.get("auth")
    })

    return {"job_id": job_id, "type": "web_scan"}


@app.post("/scan/network")
async def scan_network(req: dict, key: str = Depends(verify_api_key)):
    host = req.get("host") or req.get("url")
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
        "job_id": job_id,
        "url": host,
        "port_range": req.get("port_range"),
    })

    return {"job_id": job_id, "type": "network_scan"}


@app.post("/scan/api")
async def scan_api(req: dict, key: str = Depends(verify_api_key)):
    target_url = req.get("url")
    user_id = key

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
        "job_id": job_id,
        "url": target_url,
        "auth_token": req.get("auth_token"),
        "spec_url": req.get("spec_url"),
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
    builder.build_pdf(file_path, report["content"])
    return {"file": file_path}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("api.main:app", host="0.0.0.0", port=port, reload=False)
