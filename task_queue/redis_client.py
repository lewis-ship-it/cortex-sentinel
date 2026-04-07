import redis
import json
import os
import time
import logging

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

MAX_RETRIES = 3

def push(queue, data):
    data["retries"] = data.get("retries", 0)
    r.lpush(queue, json.dumps(data))


def pop(queue):
    data = r.rpop(queue)
    if data:
        return json.loads(data)
    return None


def retry(queue, job, error=None):
    job["retries"] = job.get("retries", 0) + 1

    if job["retries"] > MAX_RETRIES:
        logging.error(f"[DROP] Job failed permanently: {job}")
        return

    logging.warning(f"[RETRY] {queue} | Attempt {job['retries']} | Error: {error}")
    time.sleep(1)
    push(queue, job)