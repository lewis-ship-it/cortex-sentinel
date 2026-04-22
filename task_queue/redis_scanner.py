# task_queue/redis_scanner.py
# Thin wrapper kept for backward compatibility with workers/workers.py.
# All actual queue logic lives in task_queue/redis_client.py.

import logging
from task_queue.redis_client import push, pop
from task_queue.queues import SCAN_QUEUE


def enqueue_scan(data: dict) -> None:
    """Push a web-scan job onto the scan queue."""
    push(SCAN_QUEUE, data)
    logging.debug(f"[REDIS] Job enqueued: {data.get('job_id')}")


def dequeue_scan() -> dict:
    """Pop a web-scan job from the scan queue."""
    return pop(SCAN_QUEUE)