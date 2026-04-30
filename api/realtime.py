# api/realtime.py - Refactored for SQLite persistence
import logging
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
import json
import asyncio
import time
from typing import AsyncGenerator, List, Dict, Any, Optional
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum

from core.database import get_db, DatabaseManager

logger = logging.getLogger(__name__)
router = APIRouter()

class JobStatus(str, Enum):
    PENDING = "pending"
    CRAWLING = "crawling"
    SCANNING = "scanning"
    EXPLOITING = "exploiting"
    AGGREGATING = "aggregating"
    MEMORY_ENRICHING = "memory_enriching"
    SCORING = "scoring"
    REPORTING = "reporting"
    DONE = "done"
    FAILED = "failed"

@dataclass
class LogEntry:
    """Data class for log entries."""
    timestamp: str
    message: str
    level: str
    component: str
    job_id: str

@dataclass
class JobStatusResponse:
    """Data class for job status response."""
    job_id: str
    status: JobStatus
    logs: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    finding_count: int
    progress: Optional[float] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None

async def get_database() -> DatabaseManager:
    """Dependency for getting database instance."""
    return get_db()

@asynccontextmanager
async def stream_timeout_handler(timeout: int = 30):
    """Context manager for handling stream timeouts."""
    try:
        yield
    except asyncio.TimeoutError:
        logger.warning("Stream timeout occurred")
        raise HTTPException(status_code=408, detail="Stream timeout")
    except Exception as e:
        logger.error(f"Stream error: {e}")
        raise

@router.get("/api/stream-logs/{job_id}")
async def stream_logs(
    job_id: str,
    db: DatabaseManager = Depends(get_database),
    timeout: int = 30
):
    """
    Server-Sent Events stream of logs for a job using SQLite persistence.
    
    Args:
        job_id: The job ID to stream logs for
        timeout: Connection timeout in seconds (default: 30)
    
    Returns:
        StreamingResponse with SSE events
    """
    async def event_stream() -> AsyncGenerator[str, None]:
        last_index = 0
        max_retries = 3
        retry_count = 0
        
        async with stream_timeout_handler(timeout):
            while True:
                try:
                    # Fetch logs directly from SQLite instead of Redis
                    logs_raw = db.get_log_messages(job_id)
                    logs = []
                    
                    for entry in logs_raw:
                        try:
                            if isinstance(entry, str):
                                log_dict = json.loads(entry)
                            elif isinstance(entry, dict):
                                log_dict = entry
                            else:
                                continue
                                
                            # Normalize log entry structure
                            normalized_entry = {
                                "timestamp": log_dict.get("time", log_dict.get("timestamp", "")),
                                "message": log_dict.get("message", str(log_dict)),
                                "level": log_dict.get("level", "INFO"),
                                "component": log_dict.get("component", "LOG"),
                                "stage": log_dict.get("stage", log_dict.get("component", "LOG").upper())
                            }
                            logs.append(normalized_entry)
                        except (json.JSONDecodeError, TypeError) as e:
                            logger.warning(f"Failed to parse log entry: {entry}, error: {e}")
                            continue
                    
                    # Filter for new logs based on index
                    new_logs = logs[last_index:]
                    
                    for log_entry in new_logs:
                        yield f"data: {json.dumps(log_entry)}\n\n"
                    
                    last_index = len(logs)
                    
                    # Check job status
                    job_status = db.get_job_status(job_id)
                    if not job_status:
                        job_status = JobStatus.FAILED.value
                    
                    # Check if job is complete
                    if job_status in (JobStatus.DONE.value, JobStatus.FAILED.value):
                        completion_event = {
                            "type": "complete",
                            "status": job_status,
                            "message": f"Job {job_status}",
                            "timestamp": time.time()
                        }
                        yield f"data: {json.dumps(completion_event)}\n\n"
                        break
                    
                    # Reset retry count on successful iteration
                    retry_count = 0
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    retry_count += 1
                    logger.error(f"[SSE] Stream error for {job_id} (retry {retry_count}): {e}")
                    
                    if retry_count >= max_retries:
                        error_event = {
                            "type": "error",
                            "message": "Stream connection failed after multiple retries",
                            "timestamp": time.time()
                        }
                        yield f"data: {json.dumps(error_event)}\n\n"
                        break
                    
                    error_event = {
                        "type": "error",
                        "message": f"Temporary error: {str(e)}",
                        "timestamp": time.time()
                    }
                    yield f"data: {json.dumps(error_event)}\n\n"
                    await asyncio.sleep(2 ** retry_count)  # Exponential backoff
    
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

@router.get("/api/job-status/{job_id}")
async def get_job_status(
    job_id: str,
    db: DatabaseManager = Depends(get_database)
) -> JobStatusResponse:
    """
    Get current job status and findings from SQLite.
    
    Args:
        job_id: The job ID to get status for
    
    Returns:
        JobStatusResponse with job status, logs, and findings
    
    Raises:
        HTTPException: If job not found or internal error occurs
    """
    try:
        data = db.get_job_full_status(job_id)
        if not data:
            raise HTTPException(status_code=404, detail="Job not found")
        
        # Normalize logs
        logs = []
        for log_entry in data.get("logs", []):
            if isinstance(log_entry, str):
                try:
                    log_dict = json.loads(log_entry)
                except json.JSONDecodeError:
                    log_dict = {"message": log_entry, "timestamp": "", "level": "INFO"}
            else:
                log_dict = log_entry
            
            logs.append({
                "timestamp": log_dict.get("time", log_dict.get("timestamp", "")),
                "message": log_dict.get("message", str(log_dict)),
                "level": log_dict.get("level", "INFO"),
                "component": log_dict.get("component", "LOG")
            })
        
        # Get job metadata
        job_metadata = db.get_job_metadata(job_id) or {}
        
        return JobStatusResponse(
            job_id=job_id,
            status=JobStatus(data.get("status", JobStatus.FAILED.value)),
            logs=logs,
            findings=data.get("findings", []),
            finding_count=len(data.get("findings", [])),
            progress=job_metadata.get("progress"),
            start_time=job_metadata.get("start_time"),
            end_time=job_metadata.get("end_time")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[API] Error fetching status for {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/api/clear-queues")
async def clear_queues(db: DatabaseManager = Depends(get_database)):
    """
    Resets the system state machine by clearing stale or active jobs.
    
    Returns:
        Dictionary with operation status
    
    Raises:
        HTTPException: If operation fails
    """
    try:
        # Use correct lowercase status values as per database schema
        active_statuses = [
            JobStatus.PENDING.value,
            JobStatus.CRAWLING.value,
            JobStatus.SCANNING.value,
            JobStatus.EXPLOITING.value,
            JobStatus.AGGREGATING.value,
            JobStatus.MEMORY_ENRICHING.value,
            JobStatus.SCORING.value,
            JobStatus.REPORTING.value
        ]
        
        # Convert list to SQL tuple format
        status_placeholders = ",".join(["?"] * len(active_statuses))
        
        with db._conn() as con:
            result = con.execute(
                f"""UPDATE jobs SET status = ?
                WHERE status IN ({status_placeholders})""",
                [JobStatus.FAILED.value] + active_statuses
            )
            
            affected_rows = result.rowcount
            
        logger.info(f"[API] System state reset via /api/clear-queues. Affected {affected_rows} jobs.")
        
        return {
            "status": "success",
            "message": f"System queues/states reset successfully. {affected_rows} jobs marked as failed.",
            "affected_jobs": affected_rows
        }
        
    except Exception as e:
        logger.error(f"[API] Failed to reset state: {e}")
        raise HTTPException(status_code=500, detail="State reset failed")

@router.get("/api/active-jobs")
async def get_active_jobs(db: DatabaseManager = Depends(get_database)):
    """
    Get list of currently active jobs.
    
    Returns:
        List of active job IDs and their statuses
    """
    try:
        active_statuses = [
            JobStatus.PENDING.value,
            JobStatus.CRAWLING.value,
            JobStatus.SCANNING.value,
            JobStatus.EXPLOITING.value,
            JobStatus.AGGREGATING.value,
            JobStatus.MEMORY_ENRICHING.value,
            JobStatus.SCORING.value,
            JobStatus.REPORTING.value
        ]
        
        status_placeholders = ",".join(["?"] * len(active_statuses))
        
        with db._conn() as con:
            rows = con.execute(
                f"""SELECT job_id, status, created_at 
                FROM jobs 
                WHERE status IN ({status_placeholders})
                ORDER BY created_at DESC""",
                active_statuses
            ).fetchall()
        
        return {
            "active_jobs": [
                {
                    "job_id": row[0],
                    "status": row[1],
                    "created_at": row[2]
                }
                for row in rows
            ],
            "count": len(rows)
        }
        
    except Exception as e:
        logger.error(f"[API] Error fetching active jobs: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch active jobs")
