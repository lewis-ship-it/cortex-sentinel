# task_queue/redis_scanner.py
# ──────────────────────────────────────────────────────────────────────────────
# THIS FILE WAS MISSING — it is imported by:
#   • api/main.py          → enqueue_scan()
#   • workers/main_worker.py → dequeue_scan()
#
# Without this file, api/main.py falls back to _HAS_QUEUE = False and
# enqueue_scan() becomes a no-op stub.  Jobs are created in the DB but
# NEVER pushed to any Redis queue, so no worker ever picks them up.
#
# Fix: enqueue_scan() pushes to CRAWL_QUEUE (correct pipeline start).
#      dequeue_scan() pops from SCAN_QUEUE (legacy main_worker compat).
# ──────────────────────────────────────────────────────────────────────────────

from task_queue.redis_client import push, pop
from task_queue.queues import CRAWL_QUEUE, SCAN_QUEUE


def enqueue_scan(job: dict) -> bool:
    """
    Push a scan job onto the crawl queue — the correct pipeline entry point.

    Pipeline order:
        [auth_queue] (optional) → crawl_queue → scan_queue
        → exploit_queue → aggregation_queue → [memory+scoring] → report_queue

    Args:
        job: dict containing at minimum: job_id, url, tier.
             Optionally: auth, target_url, idempotency_key.

    Returns:
        True if the push succeeded, False otherwise.
    """
    # Normalise: ensure both 'url' and 'target_url' are present so downstream
    # workers that read either key work correctly.
    if "url" not in job and "target_url" in job:
        job = dict(job)
        job["url"] = job["target_url"]
    elif "target_url" not in job and "url" in job:
        job = dict(job)
        job["target_url"] = job["url"]

    job.setdefault("tier", "Basic")

    return push(CRAWL_QUEUE, job)


def dequeue_scan() -> dict | None:
    """
    Non-blocking pop from SCAN_QUEUE.

    Used by the legacy workers/main_worker.py.  Returns None immediately
    if the queue is empty (use task_queue.redis_client.blocking_pop for
    a blocking variant).
    """
    return pop(SCAN_QUEUE)