# task_queue/redis_client.py

import redis
import json
import os
import time
import logging

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

r = redis.Redis.from_url(
    REDIS_URL,
    ssl_cert_reqs=None,   # Required for cloud environments (e.g. Upstash)
    decode_responses=True
)

MAX_RETRIES = 3


def push(queue: str, data: dict) -> None:
    data["retries"] = data.get("retries", 0)
    r.lpush(queue, json.dumps(data))


def pop(queue: str):
    data = r.rpop(queue)
    if data:
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            logging.error(f"[REDIS] Failed to parse job: {e}")
            return None
    return None


def retry(queue: str, job: dict, error: str = None) -> None:
    job["retries"] = job.get("retries", 0) + 1

    if job["retries"] > MAX_RETRIES:
        logging.error(f"[DROP] Job failed permanently: {job}")
        return

    logging.warning(f"[RETRY] {queue} | Attempt {job['retries']} | Error: {error}")
    time.sleep(1)
    push(queue, job)
