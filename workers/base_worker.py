import json
import time
import redis
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

def fetch(queue):
    """Fetches a job and ensures tier enforcement is present."""
    data = r.blpop(queue, timeout=5)
    if not data:
        return None
    
    job = json.loads(data[1])
    
    # SENIOR MOVE: Hard-code a default tier. 
    # If a job somehow reaches a worker without a tier, we assume 'Basic' 
    # to protect your infrastructure/GPU from unauthorized Pro-level processing.
    if "tier" not in job:
        job["tier"] = "Basic"
        
    return job

def push_log(job_id, message, tier="Basic"):
    """Enhanced logging that can flag Tier-specific actions."""
    # We include the tier in the log entry so the Dashboard 
    # can visually distinguish between Basic and Pro processing events.
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "message": message,
        "tier": tier
    }

    r.rpush(f"logs:{job_id}", json.dumps(entry))
    r.ltrim(f"logs:{job_id}", -200, -1)  # keep last 200 logs

def worker_loop(queue, handler):
    """The heartbeat of the worker system."""
    print(f"[WORKER] Listening on {queue} | Tier-Aware Mode Active")

    while True:
        job = fetch(queue)
        if not job:
            continue

        try:
            # We pass the job into the handler, which now contains the 'tier'
            handler(job)
        except Exception as e:
            # Simplified error logging for the console
            print(f"[ERROR in {queue}] {str(e)}")
            # Log the error back to Redis for the Dashboard to see
            job_id = job.get("job_id", "unknown")
            push_log(job_id, f"CRITICAL WORKER ERROR: {str(e)}", tier=job.get("tier", "Basic"))