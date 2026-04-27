# core/counters.py
# ──────────────────────────────────────────────────────────────────────────────
# Counters with Redis-first / SQLite-fallback.
# If Redis is unavailable, falls back to the SQLite kv_store table so
# the pipeline never stalls due to a missing Redis connection.
# ──────────────────────────────────────────────────────────────────────────────

import logging

logger = logging.getLogger(__name__)

_redis = None
_use_sqlite = False


def _get_redis():
    global _redis, _use_sqlite
    if _use_sqlite:
        return None
    if _redis is not None:
        return _redis
    try:
        from task_queue.redis_client import r
        r.ping()
        _redis = r
        return _redis
    except Exception as e:
        logger.warning(f"[COUNTERS] Redis unavailable, falling back to SQLite: {e}")
        _use_sqlite = True
        return None


def _db():
    from core.database import get_db
    return get_db()


def _sqlite_hget(key: str, field: str) -> str:
    import json
    raw = _db().kv_get(key)
    if not raw:
        return None
    try:
        d = json.loads(raw)
        return str(d.get(field, ""))
    except Exception:
        return None


def _sqlite_hset(key: str, field: str, value: str) -> None:
    import json
    db = _db()
    raw = db.kv_get(key)
    d = {}
    if raw:
        try:
            d = json.loads(raw)
        except Exception:
            pass
    d[field] = value
    db.kv_set(key, json.dumps(d))


def _sqlite_hincrby(key: str, field: str, amount: int) -> int:
    import json
    db = _db()
    raw = db.kv_get(key)
    d = {}
    if raw:
        try:
            d = json.loads(raw)
        except Exception:
            pass
    current = int(d.get(field, 0))
    new_val = current + amount
    d[field] = str(new_val)
    db.kv_set(key, json.dumps(d))
    return new_val


def set_counter(job_id: str, stage: str, value: int) -> None:
    r = _get_redis()
    if r:
        r.hset(f"job:{job_id}:counts", stage, str(value))
    else:
        _sqlite_hset(f"job:{job_id}:counts", stage, str(value))


def decrement(job_id: str, stage: str) -> int:
    r = _get_redis()
    if r:
        return r.hincrby(f"job:{job_id}:counts", stage, -1)
    return _sqlite_hincrby(f"job:{job_id}:counts", stage, -1)


def get_counter(job_id: str, stage: str) -> int:
    r = _get_redis()
    if r:
        val = r.hget(f"job:{job_id}:counts", stage)
        return int(val) if val else 0
    val = _sqlite_hget(f"job:{job_id}:counts", stage)
    return int(val) if val else 0


def is_stage_done(job_id: str, stage: str) -> bool:
    return get_counter(job_id, stage) <= 0
