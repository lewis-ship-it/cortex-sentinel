import json
import time
import redis
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def fetch(queue):
    data = r.blpop(queue, timeout=5)
    if not data:
        return None
    return json.loads(data[1])



def push_log(job_id, message):
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "message": message
    }

    r.rpush(f"logs:{job_id}", json.dumps(entry))
    r.ltrim(f"logs:{job_id}", -200, -1)  # keep last 200 logs


def worker_loop(queue, handler):
    print(f"[WORKER] Listening on {queue}")

    while True:
        job = fetch(queue)
        if not job:
            continue

        try:
            handler(job)
        except Exception as e:
            print(f"[ERROR] {e}")