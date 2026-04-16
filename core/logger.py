import redis
import os
import time
import json

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def log_event(job_id, stage, message):
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "stage": stage,
        "message": message
    }

    r.rpush(f"logs:{job_id}", json.dumps(entry))
    r.ltrim(f"logs:{job_id}", -100, -1)