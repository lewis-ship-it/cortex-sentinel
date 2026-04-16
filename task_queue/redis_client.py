# task_queue/redis_client.py
#
# FIX 1 — Redis Error 111 in Docker:
#   REDIS_URL now reads from environment. docker-compose.yml must set
#   REDIS_URL=redis://redis:6379 for all worker/api containers.
#   The default "redis://localhost:6379" only works for local non-Docker dev.
#
# FIX 2 — datetime.now() bug:
#   Was: from datetime import datetime  (module not imported correctly)
#   Was: str(datetime.now())            (AttributeError on the module object)
#   Fix: import datetime; datetime.datetime.now()
#
# FIX 3 — Added get_redis_connection() used by browser_worker.py

import redis
import json
import os
import datetime
import time
import logging

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CONNECTION
# Docker: set REDIS_URL=redis://redis:6379 in docker-compose env_file / environment
# Local:  set REDIS_URL=redis://localhost:6379 in .env  (or leave as default)
# ─────────────────────────────────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

_client: redis.Redis | None = None


def _connect() -> redis.Redis | None:
    global _client
    if _client is not None:
        return _client
    try:
        c = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=3)
        c.ping()
        _client = c
        logger.info(f"[REDIS] Connected → {REDIS_URL}")
    except Exception as e:
        logger.error(f"[REDIS] Cannot connect to {REDIS_URL}: {e}")
        _client = None
    return _client


# Expose the bare client for modules that need direct access (pipeline.py, etc.)
r = _connect()


def get_redis_connection() -> redis.Redis | None:
    """Return the shared Redis client (lazy-reconnect on failure)."""
    return _connect()


# ─────────────────────────────────────────────────────────────────────────────
# QUEUE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def push(queue_name: str, data: dict) -> None:
    c = _connect()
    if not c:
        logger.error(f"[REDIS] push({queue_name}) skipped — no connection")
        return
    try:
        c.rpush(queue_name, json.dumps(data))
    except Exception as e:
        logger.error(f"[REDIS] push error on {queue_name}: {e}")


def pop(queue_name: str) -> dict | None:
    """Non-blocking pop. Returns None if queue is empty or Redis is down."""
    c = _connect()
    if not c:
        return None
    try:
        data = c.lpop(queue_name)
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"[REDIS] pop error on {queue_name}: {e}")
        return None


def retry(queue: str, job: dict, error: str = None, max_retries: int = 3) -> None:
    """Re-queue a failed job with an exponential back-off."""
    job["retries"] = job.get("retries", 0) + 1
    if job["retries"] > max_retries:
        logger.error(f"[DROP] Job {job.get('job_id')} permanently failed ({error})")
        return
    wait = 2 ** job["retries"]
    logger.warning(f"[RETRY] {queue} attempt {job['retries']}/{max_retries} in {wait}s: {error}")
    time.sleep(wait)
    push(queue, job)


def log_event(job_id: str | None, stage: str, message: str) -> None:
    """Append a timestamped log entry visible in the Streamlit dashboard."""
    if not job_id:
        return
    c = _connect()
    if not c:
        return
    try:
        entry = {
            # FIX: was datetime.now() — module not class. Now correct.
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "stage": stage.upper(),
            "message": message,
        }
        c.lpush(f"logs:{job_id}", json.dumps(entry))
        c.ltrim(f"logs:{job_id}", 0, 99)
    except Exception as e:
        logger.debug(f"[REDIS] log_event error: {e}")
