import redis
import json
import logging
import os
import time

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MAX_RETRIES = 3

# Initialize Redis Connection
try:
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True, ssl_cert_reqs=None)
except Exception as e:
    logging.error(f"[REDIS] Failed to initialize: {e}")
    r = None

def push(queue, data):
    if not data or r is None:
        logging.warning(f"[REDIS] Push failed: No data or no connection to {queue}")
        return

    try:
        r.rpush(queue, json.dumps(data))
    except Exception as e:
        logging.error(f"[REDIS] Push error: {e}")

def pop(queue):
    if r is None:
        return None
    try:
        data = r.lpop(queue)
        if data is None:
            return None
        return json.loads(data)
    except Exception as e:
        logging.error(f"[REDIS] Pop error: {e}")
        return None

# --- THE RESTORED RETRY LOGIC ---
def retry(queue: str, job: dict, error: str = None) -> None:
    """
    Re-queues a failed job with exponential backoff.
    Drops the job if it exceeds MAX_RETRIES.
    """
    if r is None:
        logging.error("[DROP] Redis connection missing during retry attempt.")
        return

    # Initialize or increment retry count
    job["retries"] = job.get("retries", 0) + 1

    if job["retries"] > MAX_RETRIES:
        logging.error(f"[DROP] Job {job.get('job_id')} failed permanently: {error}")
        # Optionally: log_event(job['job_id'], "error", "Job dropped after max retries")
        return

    logging.warning(f"[RETRY] {queue} attempt {job['retries']}: {error}")

    # Exponential Backoff: Wait longer with each failure (2s, 4s, 8s)
    time.sleep(2 ** job["retries"])

    try:
        r.rpush(queue, json.dumps(job))
    except Exception as e:
        logging.error(f"[DROP] Redis down during retry: {e}")