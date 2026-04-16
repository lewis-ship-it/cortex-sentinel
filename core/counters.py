import redis
import os
import json

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def set_counter(job_id, stage, value):
    r.hset(f"job:{job_id}:counts", stage, value)


def decrement(job_id, stage):
    return r.hincrby(f"job:{job_id}:counts", stage, -1)


def get_counter(job_id, stage):
    val = r.hget(f"job:{job_id}:counts", stage)
    return int(val) if val else 0


def is_stage_done(job_id, stage):
    return get_counter(job_id, stage) <= 0