# core/session_store.py
# ──────────────────────────────────────────────────────────────────────────────
# FIX — Crash on import when Redis is unavailable
#   Old code called redis.Redis.from_url() at module level (top of file).
#   Any worker that imported session_store would crash immediately if Redis
#   was not yet reachable (common during Docker startup race conditions).
#
#   Fixed: all Redis access is now lazy — obtained per-call via
#   task_queue.redis_client.get_redis_connection(), which handles reconnects
#   and returns None gracefully if Redis is still unreachable.
#   Functions return safe defaults (None / no-op) on connection failure.
# ──────────────────────────────────────────────────────────────────────────────

import json
import logging

logger = logging.getLogger(__name__)


def _r():
    """Return the shared Redis client, or None if unavailable."""
    try:
        from task_queue.redis_client import get_redis_connection
        return get_redis_connection()
    except Exception:
        return None


def save_session(job_id: str, session_data: dict) -> bool:
    """Persist session data (cookies, headers) keyed by job_id."""
    r = _r()
    if not r:
        logger.warning(f"[SESSION] Redis unavailable — session for {job_id} not saved")
        return False
    try:
        r.set(f"session:{job_id}", json.dumps(session_data), ex=86400)  # 24h TTL
        return True
    except Exception as e:
        logger.error(f"[SESSION] save_session failed for {job_id}: {e}")
        return False


def get_session(job_id: str) -> dict | None:
    """Retrieve session data for a job, or None if not found / Redis down."""
    r = _r()
    if not r:
        return None
    try:
        raw = r.get(f"session:{job_id}")
        return json.loads(raw) if raw else None
    except Exception as e:
        logger.error(f"[SESSION] get_session failed for {job_id}: {e}")
        return None


def delete_session(job_id: str) -> None:
    """Remove session data for a job."""
    r = _r()
    if not r:
        return
    try:
        r.delete(f"session:{job_id}")
    except Exception as e:
        logger.debug(f"[SESSION] delete_session failed for {job_id}: {e}")