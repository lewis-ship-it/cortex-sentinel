import threading
import uuid
import os
import uvicorn
from fastapi import FastAPI, Request, Security, HTTPException, Depends
from fastapi.security.api_key import APIKeyHeader
from contextlib import asynccontextmanager
from dotenv import load_dotenv

from task_queue.redis_scanner import enqueue_scan
from core.job_manager import create_job, get_job
from core.database import DatabaseManager

load_dotenv()

def run_worker_in_background():
    # This now matches the function we added to worker.py
    from workers.worker import start_worker_loop 
    print("🛠️  Worker Thread: Starting...")
    start_worker_loop()

@asynccontextmanager
async def lifespan(app: FastAPI):
    worker_thread = threading.Thread(target=run_worker_in_background, daemon=True)
    worker_thread.start()
    yield

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

@app.post("/scan")
def scan(req: dict):
    target_url = req.get("url")
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing url")
    job_id = str(uuid.uuid4())
    try:
        create_job(job_id, target_url)
        enqueue_scan({"job_id": job_id, "url": target_url, "auth": req.get("auth")})
        return {"job_id": job_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/job/{job_id}")
def job_status(job_id: str):
    job = get_job(job_id)
    if not job: raise HTTPException(status_code=404, detail="Job not found")
    return job

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    # Using the module string "main:app" ensures Uvicorn correctly resolves the app attribute
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)