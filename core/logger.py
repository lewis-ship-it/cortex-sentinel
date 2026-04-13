import redis
import json
import time
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True, ssl_cert_reqs=None)

current_stage = None

def set_stage(stage: str):
    global current_stage
    current_stage = stage
    print(f"[STAGE] {stage}")


def log_event(job_id, stage, message):
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "stage": stage,
        "message": message
    }

    r.rpush(f"log:{job_id}", json.dumps(entry))
    r.ltrim(f"log:{job_id}", -100, -1)  # keep last 100 logs