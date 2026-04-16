# workers/memory_worker.py

from workers.base_worker import worker_loop, push_log
from task_queue.queues import MEMORY_QUEUE
import redis
import os
import json

r = redis.Redis.from_url(os.getenv("REDIS_URL"), decode_responses=True)


def store_memory(target, findings):
    key = f"memory:{target}"

    existing = r.get(key)
    history = json.loads(existing) if existing else []

    history.append(findings)

    r.set(key, json.dumps(history))


def handle(job):
    job_id = job["job_id"]
    findings = job["findings"]
    target = job.get("target", "unknown")

    push_log(job_id, "[MEMORY] Learning from scan")

    store_memory(target, findings)

    push_log(job_id, "[MEMORY] Stored")


if __name__ == "__main__":
    worker_loop(MEMORY_QUEUE, handle)