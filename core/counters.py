# core/counters.py
# ──────────────────────────────────────────────────────────────────────────────
# Job counters — tracks how many scan tasks remain per job.
# Uses Redis when available, falls back to SQLite KV store.
#
# FIX: Previous version imported `r` directly at module level, which would
# crash if Redis was unavailable. Now uses lazy get_redis_connection()
# with SQLite fallback via db.kv_set/kv_get.
# ──────────────────────────────────────────────────────────────────────────────

import json
import logging

logger = logging.getLogger(__name__)


def _get_redis():
    try:
        from task_queue.redis_client import get_redis_connection
        return get_redis_connection()
    except Exception:
        return None


def _get_db():
    try:
        from core.database import get_db
        return get_db()
    except Exception:
        return None


def set_counter(job_id: str, stage: str, value: int) -> None:
    client = _get_redis()
    if client:
        try:
            client.hset(f"job:{job_id}:counts", stage, str(value))
            return
        except Exception:
            pass

    # Fallback: SQLite KV store
    db = _get_db()
    if db:
        try:
            key = f"counter:{job_id}:{stage}"
            db.kv_set(key, str(value))
        except Exception as e:
            logger.warning(f"set_counter fallback failed: {e}")


def decrement(job_id: str, stage: str) -> int:
    client = _get_redis()
    if client:
        try:
            return int(client.hincrby(f"job:{job_id}:counts", stage, -1))
        except Exception:
            pass

    # Fallback: SQLite KV store (read-decrement-write)
    db = _get_db()
    if db:
        try:
            key = f"counter:{job_id}:{stage}"
            raw = db.kv_get(key)
            current = int(raw) if raw else 0
            new_val = current - 1
            db.kv_set(key, str(new_val))
            return new_val
        except Exception as e:
            logger.warning(f"decrement fallback failed: {e}")

    return 0


def get_counter(job_id: str, stage: str) -> int:
    client = _get_redis()
    if client:
        try:
            val = client.hget(f"job:{job_id}:counts", stage)
            return int(val) if val else 0
        except Exception:
            pass

    # Fallback: SQLite KV store
    db = _get_db()
    if db:
        try:
            key = f"counter:{job_id}:{stage}"
            raw = db.kv_get(key)
            return int(raw) if raw else 0
        except Exception as e:
            logger.warning(f"get_counter fallback failed: {e}")

    return 0


def is_stage_done(job_id: str, stage: str) -> bool:
    return get_counter(job_id, stage) <= 0
