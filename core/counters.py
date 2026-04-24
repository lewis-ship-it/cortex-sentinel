# core/counters.py
# ──────────────────────────────────────────────────────────────────────────────
# SQLite-backed counters — drop-in replacement for the Redis version.
# Uses the _RedisShim hash ops which write to the kv_store table.
# ──────────────────────────────────────────────────────────────────────────────

# core/counters.py
from task_queue.redis_client import get_redis_connection  # ✅ lazy, reconnects on demand

def set_counter(job_id: str, stage: str, value: int) -> None:
    client = get_redis_connection()
    if not client:
        return
    client.hset(f"job:{job_id}:counts", stage, str(value))

def decrement(job_id: str, stage: str) -> int:
    client = get_redis_connection()
    if not client:
        return 0
    return int(client.hincrby(f"job:{job_id}:counts", stage, -1))

def get_counter(job_id: str, stage: str) -> int:
    client = get_redis_connection()
    if not client:
        return 0
    val = client.hget(f"job:{job_id}:counts", stage)
    return int(val) if val else 0

def is_stage_done(job_id: str, stage: str) -> bool:
    return get_counter(job_id, stage) <= 0