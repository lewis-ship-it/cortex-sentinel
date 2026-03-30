from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uuid

from queue.redis_queue import enqueue_scan
from core.job_manager import create_job, get_job
from core.database import DatabaseManager

app = FastAPI()
db = DatabaseManager()

API_KEYS = {"test-key-123"}

@app.middleware("http")
async def auth(request: Request, call_next):
    if request.url.path.startswith("/auth"):
        return await call_next(request)
    key = request.headers.get("x-api-key")
    if key not in API_KEYS:
        return JSONResponse(status_code=403, content={"error": "Unauthorized"})
    return await call_next(request)

@app.post("/scan")
def scan(req: dict):
    job_id = str(uuid.uuid4())
    create_job(job_id, req["url"])
    enqueue_scan({
        "job_id": job_id,
        "url": req["url"]
    })
    return {"job_id": job_id}

@app.get("/job/{job_id}")
def job(job_id: str):
    return get_job(job_id)

@app.get("/result/{job_id}")
def result(job_id: str):
    vulns = db.get_results(job_id)
    return {"vulnerabilities": vulns}
