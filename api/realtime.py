# api/realtime.py - Refactored for SQLite persistence
import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
import json
import asyncio
import time
from typing import Generator, List
from core.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter()
db = get_db()

@router.get("/api/stream-logs/{job_id}")
async def stream_logs(job_id: str):
    """
    Server-Sent Events stream of logs for a job using SQLite persistence.
    """
    async def event_stream() -> Generator[str, None, None]:
        last_index = 0
        
        while True:
            try:
                # Fetch logs directly from SQLite instead of Redis
                logs_raw = db.get_log_messages(job_id)
                logs = []
                for entry in logs_raw:
                    log_dict = json.loads(entry) if isinstance(entry, str) else entry
                    log_dict["timestamp"] = log_dict.get("time", "")
                    log_dict["stage"] = log_dict.get("tier", "LOG") # Map tier to stage
                    logs.append(log_dict)
                
                # Filter for new logs based on index
                new_logs = logs[last_index:]
                
                for log_entry in new_logs:
                    # Maintain existing format compatibility
                    data = log_entry if isinstance(log_entry, dict) else {"message": log_entry}
                    yield f"data: {json.dumps(data)}\n\n"
                
                last_index = len(logs)
                
                # Check job status in SQLite
                job_status = db.get_job_status(job_id) # Assumes this helper exists
                if job_status == "done":
                    yield f"data: {json.dumps({'type': 'complete', 'message': 'Job finished'})}\n\n"
                    break
                
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"[SSE] Stream error for {job_id}: {e}")
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
                await asyncio.sleep(1)
    
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )

@router.get("/api/job-status/{job_id}")
async def get_job_status(job_id: str):
    """
    Get current job status and findings from SQLite.
    """
    try:
        # Unified database retrieval
        data = db.get_job_full_status(job_id)
        if not data:
            raise HTTPException(status_code=404, detail="Job not found")
        
        return {
            "job_id": job_id,
            "status": data.get("status", "running"),
            "logs": data.get("logs", []),
            "findings": data.get("findings", []),
            "finding_count": len(data.get("findings", [])),
        }
    except Exception as e:
        logger.error(f"[API] Error fetching status for {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# api/realtime.py

@router.post("/api/clear-queues")
async def clear_queues():
    """
    Resets the system state machine by clearing 'stale' or active jobs.
    This replaces the legacy Redis queue clearance logic.
    """
    try:
        # Atomic reset: Mark all currently RUNNING/QUEUED jobs as FAILED
        # to prevent them from blocking the worker pipeline.
        with db._conn() as con:
            con.execute(
                "UPDATE jobs SET status = 'FAILED' WHERE status IN ('RUNNING', 'QUEUED')"
            )
            
        logger.info("[API] System state reset via /api/clear-queues")
        return {"status": "success", "message": "System queues/states reset successfully."}
        
    except Exception as e:
        logger.error(f"[API] Failed to reset state: {e}")
        raise HTTPException(status_code=500, detail="State reset failed")