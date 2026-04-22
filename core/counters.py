# core/counters.py
# ──────────────────────────────────────────────────────────────────────────────
# SQLite-backed counters — drop-in replacement for the Redis version.
# Uses the _RedisShim hash ops which write to the kv_store table.
# ──────────────────────────────────────────────────────────────────────────────

from task_queue.redis_client import r


def set_counter(job_id: str, stage: str, value: int) -> None:
    r.hset(f"job:{job_id}:counts", field=stage, value=str(value))


def decrement(job_id: str, stage: str) -> int:
    return r.hincrby(f"job:{job_id}:counts", stage, -1)


def get_counter(job_id: str, stage: str) -> int:
    val = r.hget(f"job:{job_id}:counts", stage)
    return int(val) if val else 0


def is_stage_done(job_id: str, stage: str) -> bool:
    return get_counter(job_id, stage) <= 0