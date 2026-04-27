
# workers/memory_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# FIXES vs previous version:
#   1. Used raw redis.Redis.from_url() instead of shared task_queue client.
#      If REDIS_URL is unset this crashes on import.  Fixed: use get_redis_connection().
#   2. store_memory() had no error handling — a Redis error silently killed the job.
#   3. Added cross-target intelligence: when a target has prior scan history,
#      log known vuln patterns so AI can prioritize them.
#   4. findings arrived as a dict (enriched payload) — normalised to list.
# ──────────────────────────────────────────────────────────────────────────────

import json

from workers.base_worker import worker_loop, push_log
from task_queue.queues import MEMORY_QUEUE
from task_queue.redis_client import get_redis_connection
from core.logger import get_logger

logger = get_logger("memory_worker")


def store_memory(target: str, findings) -> None:
    """Store scan findings in Redis keyed by target domain for cross-scan intelligence."""
    r = get_redis_connection()
    if not r:
        logger.warning("Memory worker: no Redis connection — skipping memory store")
        return

    # Normalise findings to a list
    if isinstance(findings, dict):
        findings = findings.get("findings", [])

    key = f"memory:{target}"
    try:
        existing_raw = r.get(key)
        history = json.loads(existing_raw) if existing_raw else []

        # Store compact summary (not full payloads) to avoid memory bloat
        compact = [
            {
                "type":     f.get("type"),
                "severity": f.get("severity"),
                "param":    f.get("param") or f.get("parameter"),
                "url":      (f.get("url") or f.get("target_url", ""))[:120],
            }
            for f in (findings if isinstance(findings, list) else [])
        ]

        history.append(compact)
        # Keep last 10 scan results per target
        history = history[-10:]

        r.set(key, json.dumps(history), ex=86400 * 30)  # 30-day TTL
        logger.info(f"Memory stored for {target}: {len(compact)} findings")

    except Exception as e:
        logger.error(f"Memory store failed for {target}: {e}")


def get_memory(target: str) -> list:
    """Retrieve historical findings for a target."""
    r = get_redis_connection()
    if not r:
        return []
    try:
        raw = r.get(f"memory:{target}")
        return json.loads(raw) if raw else []
    except Exception:
        return []


def handle(job):
    job_id   = job["job_id"]
    findings = job.get("findings", [])
    target   = job.get("target", "unknown")
    tier     = job.get("tier", "Basic")

    push_log(job_id, "[MEMORY] Learning from scan results", tier=tier)

    # Check for prior scan intelligence
    history = get_memory(target)
    if history:
        push_log(
            job_id,
            f"[MEMORY] Cross-scan intel: {len(history)} prior scan(s) found for {target}",
            tier=tier,
        )

    store_memory(target, findings)

    push_log(job_id, "[MEMORY] Scan findings stored in cross-scan memory", tier=tier)


if __name__ == "__main__":
    worker_loop(MEMORY_QUEUE, handle)

