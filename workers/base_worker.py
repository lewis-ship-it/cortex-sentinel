# workers/base_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# FIXES IN THIS VERSION
#
# BUG 1 (CRITICAL) — Dual-store split: logs were written to Redis only.
#   push_log() called client.rpush(f"logs:{job_id}", ...) into Redis.
#   /api/status reads from SQLite (db.get_log_messages()).
#   These two stores never communicate — every worker log was invisible to
#   the dashboard.
#
#   FIX: push_log() now writes to SQLite (db.add_log()) as the primary store
#   AND to Redis as a secondary store for SSE stream compatibility.
#   SQLite is the single source of truth the API and dashboard read from.
#
# BUG 6 — Stage label always "[BASIC]" or "[PROFESSIONAL]"
#   The old entry stored {time, message, tier}. The JS rendered logData.tier
#   as the coloured stage label, producing "[BASIC]" on every line.
#
#   FIX: push_log() now derives a `component` / `stage` label from the
#   message prefix (e.g. "[SCAN]" → component="scan") and stores it
#   alongside the message so the JS can render the correct label.
# ──────────────────────────────────────────────────────────────────────────────

import json
import logging
import re
import time as _time

from task_queue.redis_client import blocking_pop, get_redis_connection

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# LOG WRITER  — SQLite primary, Redis secondary
# ─────────────────────────────────────────────────────────────────────────────

def push_log(job_id: str, message: str, tier: str = "Basic", component: str = None) -> None:
    """
    Append a structured log entry to both SQLite and Redis.

    SQLite is the authoritative store read by /api/status and the dashboard.
    Redis is kept as a secondary write for the SSE stream (/api/stream/<id>).

    Parameters
    ──────────
    job_id    : The scan job this log belongs to.
    message   : Human-readable log message (may include a [TAG] prefix).
    tier      : "Basic" or "Professional" — stored for filtering.
    component : Explicit component name (e.g. "scan", "crawl").  If omitted,
                derived automatically from the [TAG] prefix in `message`.
    """
    # ── Derive component label from message prefix ────────────────────────────
    # "[SCAN] Starting scan…"  → component = "scan"
    # "[EXPLOIT] Running…"     → component = "exploit"
    # "Some message"           → component = "worker"
    if component is None:
        m = re.match(r'\[([A-Z_0-9]+)\]', message.strip())
        component = m.group(1).lower() if m else "worker"

    # ── SQLite write (primary — what /api/status reads) ───────────────────────
    try:
        from core.database import get_db
        get_db().add_log(
            job_id,
            message,
            level="INFO",
            component=component,
            tier=tier,
        )
    except Exception as e:
        # Never let a logging failure kill a worker
        logger.warning(f"[LOG] SQLite write failed for {job_id}: {e}")

    # ── Redis write (secondary — kept for SSE stream) ─────────────────────────
    client = get_redis_connection()
    if client:
        entry = {
            "time":      _time.strftime("%H:%M:%S"),
            "message":   message,
            "tier":      tier,
            "component": component,
            "stage":     component.upper(),   # JS log renderer reads "stage"
        }
        try:
            key = f"logs:{job_id}"
            client.rpush(key, json.dumps(entry))
            client.ltrim(key, -500, -1)       # keep last 500 entries
        except Exception as e:
            logger.debug(f"[LOG] Redis write failed for {job_id}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# QUEUE FETCH
# ─────────────────────────────────────────────────────────────────────────────

def fetch(queue: str) -> dict | None:
    """
    Blocking pop with 5 s timeout.  Returns the job dict or None on timeout.
    Sets a default tier of "Basic" if the job omits it.
    """
    job = blocking_pop(queue, timeout=5)
    if not job:
        return None
    job.setdefault("tier", "Basic")
    return job
#____________________________________________________________________________________
#wrapper for fetch to handle exceptions and ensure it always returns a dict or None
#____________________________________________________________________________________
def pop_queue(queue: str) -> dict | None:
    """
    Non-blocking pop from the queue. Returns the job dict or None if empty.
    This is an alias for fetch() for compatibility.
    """
    return fetch(queue)



# ─────────────────────────────────────────────────────────────────────────────
# WORKER LOOP
# ─────────────────────────────────────────────────────────────────────────────

def worker_loop(queue: str, handler) -> None:
    """
    Heartbeat loop: fetch jobs from `queue` and dispatch to `handler`.

    Any exception that escapes `handler` is logged and the loop continues —
    one bad job must never kill the worker process.
    """
    print(f"[WORKER] Listening on '{queue}'")

    while True:
        try:
            job = fetch(queue)
            if not job:
                continue

            job_id = job.get("job_id", "unknown")
            tier   = job.get("tier", "Basic")

            push_log(job_id, f"[{queue.upper()}] Processing started", tier=tier)
            handler(job)
            push_log(job_id, f"[{queue.upper()}] Processing completed", tier=tier)

        except KeyboardInterrupt:
            print(f"\n[WORKER] {queue} — shutdown requested.")
            break
        except Exception as exc:
            logger.error(
                f"[WORKER] Unhandled exception in {queue}: {exc}", exc_info=True
            )
            _time.sleep(2)   # brief back-off to prevent rapid crash loops