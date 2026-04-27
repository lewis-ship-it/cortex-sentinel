# task_queue/redis_client.py
#
# FIX 1 — Redis Error 111 in Docker:
#   REDIS_URL reads from environment.  docker-compose.yml must set
#   REDIS_URL=redis://redis:6379 for all worker/api containers.
#   The default "redis://localhost:6379" only works for local non-Docker dev.
#
# FIX 2 — datetime.now() AttributeError:
#   Was: from datetime import datetime / str(datetime.now())
#   Was: treating the *module* as the class.
#   Fix: import datetime; datetime.datetime.now()
#
# FIX 3 — get_redis_connection() exposed for browser_worker.py etc.
#
# FIX 4 — clear_queues() flushes all worker queues at API startup so stale
#   jobs from a previous container lifecycle never re-enter the pipeline.
#   Called once in api/main.py lifespan startup hook.
#
# FIX 5 — retry() replaced with retry_job() backed by true exponential
#   back-off (2^n seconds, cap 60s, +jitter) instead of bare time.sleep().
#
# FIX 6 — NEW: blocking_pop() added for worker loops (BLPOP with timeout)

import redis
import json
import os
import datetime
import time
import random
import logging
from typing import Optional, List

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CONNECTION
# Docker: set REDIS_URL=redis://redis:6379 in docker-compose env / env_file
# Local:  set REDIS_URL=redis://localhost:6379 in .env (or leave as default)
# ─────────────────────────────────────────────────────────────────────────────

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

_client: Optional[redis.Redis] = None


def _connect() -> Optional[redis.Redis]:
    """Return a live Redis client, (re)connecting if the connection is stale."""
    global _client

    # Fast path — client exists and is healthy
    if _client is not None:
        try:
            _client.ping()
            return _client
        except Exception:
            _client = None  # stale — fall through and reconnect

    try:
        c = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_keepalive=True,
            retry_on_timeout=True,
        )
        c.ping()
        _client = c
        logger.info(f"[REDIS] Connected → {REDIS_URL}")
    except Exception as e:
        logger.error(f"[REDIS] Cannot connect to {REDIS_URL}: {e}")
        _client = None

    return _client


# Bare client exposed for modules that need direct Redis access (pipeline.py…)
r = _connect()


def get_redis_connection() -> Optional[redis.Redis]:
    """Return the shared Redis client, lazy-reconnecting on failure."""
    return _connect()


# ─────────────────────────────────────────────────────────────────────────────
# ALL KNOWN QUEUE NAMES
# (kept here to avoid circular imports from task_queue/queues.py)
# ─────────────────────────────────────────────────────────────────────────────

_ALL_QUEUES: List[str] = [
    "crawl_queue",
    "scan_queue",
    "browser_queue",
    "sast_queue",
    "exploit_queue",
    "aggregation_queue",
    "report_queue",
    "network_queue",
    "mobile_queue",
    "api_queue",
    "planner_queue",
    "memory_queue",
    "scoring_queue",
    "auth_queue",
]


# ─────────────────────────────────────────────────────────────────────────────
# STARTUP QUEUE FLUSH  (Fix #4)
# ─────────────────────────────────────────────────────────────────────────────

def clear_queues(queues: Optional[List[str]] = None) -> None:
    """
    DELETE all items from every worker queue.

    Call this ONCE at application startup (api/main.py lifespan) to guarantee
    a clean slate.  Without this, jobs that were mid-flight when a previous
    container was killed will re-enter workers on restart and produce:
        • duplicate / phantom scans
        • reports generated for stale findings
        • corrupted pipeline state (wrong tier, missing job_id context)

    Usage in api/main.py::

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            from task_queue.redis_client import clear_queues
            clear_queues()
            print("🚀 Sentinel API Online")
            yield
            print("🛑 Sentinel API Shutting down")

    Args:
        queues: list of queue names to flush. Defaults to all known queues.
    """
    c = _connect()
    if not c:
        logger.warning("[REDIS] clear_queues: no connection — skipping flush")
        return

    target = queues or _ALL_QUEUES
    total_deleted = 0

    for q in target:
        try:
            n = c.delete(q)
            if n:
                logger.info(f"[REDIS] Flushed '{q}' — {n} stale item(s) removed")
                total_deleted += n
        except Exception as e:
            logger.error(f"[REDIS] clear_queues failed for '{q}': {e}")

    logger.info(
        f"[REDIS] Startup queue flush complete — "
        f"{total_deleted} stale item(s) removed across {len(target)} queues"
    )


# ─────────────────────────────────────────────────────────────────────────────
# QUEUE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def push(queue_name: str, data: dict) -> None:
    """
    Push a JSON payload onto the right end of a Redis list queue.
    Now includes internal retry logic to handle transient connection blips.
    """
    max_retries = 5
    for attempt in range(max_retries):
        c = _connect() # Assuming this is your existing connection helper
        if not c:
            logger.warning(f"[REDIS] Attempt {attempt+1}: No connection for {queue_name}")
            time.sleep(2)
            continue

        try:
            c.rpush(queue_name, json.dumps(data))
            return True # Success
        except Exception as e:
            logger.warning(f"[REDIS] Attempt {attempt+1}: Push failed for {queue_name}: {e}")
            time.sleep(2) # Backoff

    logger.error(f"[REDIS] CRITICAL: Failed to push to {queue_name} after {max_retries} attempts.")
    return False


def pop(queue_name: str) -> Optional[dict]:
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


# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING POP — NEW FUNCTION (Fix #6)
# ─────────────────────────────────────────────────────────────────────────────

def blocking_pop(queue_name: str, timeout: int = 5) -> Optional[dict]:
    """
    Blocking pop with timeout. Waits for an item to appear in the queue.
    
    Uses Redis BLPOP which blocks the connection until an item is available
    or the timeout is reached. This is more efficient than polling with pop().
    
    Args:
        queue_name: Redis queue name to pop from
        timeout: Seconds to wait for an item (default 5)
        
    Returns:
        Dict if job found, None if timeout or Redis error
    """
    c = _connect()
    if not c:
        return None
    try:
        # BLPOP returns tuple: (queue_name, value) or None on timeout
        result = c.blpop(queue_name, timeout=timeout)
        if result:
            _, data = result
            return json.loads(data)
        return None
    except Exception as e:
        logger.error(f"[REDIS] blocking_pop error on {queue_name}: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def log_event(job_id: Optional[str], stage: str, message: str) -> None:
    """Append a timestamped log entry visible in the Streamlit dashboard."""
    if not job_id:
        return
    c = _connect()
    if not c:
        return
    try:
        entry = {
            # FIX: was datetime.now() — module not class.
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "stage":     stage.upper(),
            "message":   message,
        }
        c.lpush(f"logs:{job_id}", json.dumps(entry))
        c.ltrim(f"logs:{job_id}", 0, 199)
    except Exception as e:
        logger.debug(f"[REDIS] log_event error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# JOB RETRY WITH EXPONENTIAL BACK-OFF  (Fix #5)
# ─────────────────────────────────────────────────────────────────────────────

def retry_job(
    queue:       str,
    job:         dict,
    error:       Optional[str] = None,
    max_retries: int = 4,
) -> None:
    """
    Re-queue a failed job with exponential back-off and jitter.

    Back-off schedule (seconds before re-queuing):
        attempt 1 → ~2s   (2¹ + jitter)
        attempt 2 → ~4s   (2² + jitter)
        attempt 3 → ~8s   (2³ + jitter)
        attempt 4 → ~16s  (2⁴ + jitter)
        attempt 5 → job is DROPPED permanently

    Unlike the old ``time.sleep(2 ** retries)`` approach this:
    • caps wait at 60 s so a stuck job doesn't block a worker for minutes
    • adds ±1 s random jitter to prevent "thundering herd" when many workers
      retry at exactly the same moment
    • logs both the retry attempt and the permanent drop for observability

    Args:
        queue:       Redis queue name to re-push the job onto
        job:         The original job dict (not mutated)
        error:       Human-readable failure reason for logging
        max_retries: Maximum number of re-queue attempts before permanent drop
    """
    job = dict(job)                          # never mutate the caller's dict
    job["retries"] = job.get("retries", 0) + 1

    if job["retries"] > max_retries:
        logger.error(
            f"[DROP] Job {job.get('job_id')} permanently failed after "
            f"{max_retries} retries. Last error: {error}"
        )
        return

    # Exponential back-off: 2^retries capped at 60 s, plus ≤1 s jitter
    wait = min(2 ** job["retries"], 60) + random.uniform(0, 1.0)
    logger.warning(
        f"[RETRY] queue={queue}  attempt={job['retries']}/{max_retries}  "
        f"sleep={wait:.1f}s  reason={error}"
    )
    time.sleep(wait)
    push(queue, job)


# Backward-compatible alias — old code calls retry(queue, job, error)
retry = retry_job

