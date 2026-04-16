# core/pipeline.py

import json
import redis
import os

from task_queue.redis_client import push
from task_queue.queues import (
    SCAN_QUEUE,
    BROWSER_QUEUE,
    EXPLOIT_QUEUE,
    AGGREGATION_QUEUE,
    REPORT_QUEUE,
    PLANNER_QUEUE,
    MEMORY_QUEUE,
    SCORING_QUEUE
)


from core.counters import set_counter, decrement
from core.database import DatabaseManager

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

db = DatabaseManager()


# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
def log(job_id, msg):
    r.rpush(f"logs:{job_id}", msg)
    r.ltrim(f"logs:{job_id}", -100, -1)


# ─────────────────────────────────────────────
# SCAN COMPLETE - SIMPLIFIED FOR NOW
# ─────────────────────────────────────────────
def on_scan_complete(job_id, findings):
    """Scan finished - store findings and mark job as done"""
    if findings:
        r.rpush(f"job:{job_id}:findings", json.dumps(findings))
    
    # Mark job complete
    db.update_job(job_id, status="done", progress=100)
    log(job_id, f"[SCAN] Complete → {len(findings)} findings stored → Job finished")


# ─────────────────────────────────────────────
# CRAWL COMPLETE → TRIGGER SCAN + BROWSER
# ─────────────────────────────────────────────
def on_crawl_complete(job_id, urls, auth=None):
    if not urls:
        db.update_job(job_id, status="failed", progress=100)
        log(job_id, "[CRAWL] No URLs found")
        return

    total_tasks = len(urls) * 2  # HTTP + Browser scans

    set_counter(job_id, "scan", total_tasks)
    db.update_job(job_id, status="scanning", progress=25)

    for url in urls:
        # HTTP scanner
        push(SCAN_QUEUE, {
            "job_id": job_id,
            "url": url,
            "auth": auth
        })

        # Browser scanner
        push(BROWSER_QUEUE, {
            "job_id": job_id,
            "url": url,
            "auth": auth
        })

    log(job_id, f"[CRAWL] {len(urls)} URLs → {total_tasks} scan tasks queued")


# ─────────────────────────────────────────────
# EXPLOIT COMPLETE
# ─────────────────────────────────────────────
def on_exploit_complete(job_id, findings):
    set_counter(job_id, "aggregation", 1)
    # send to planner FIRST
    push(PLANNER_QUEUE, {
        "job_id": job_id,
        "findings": findings
    })

    # THEN continue normal flow
    push(AGGREGATION_QUEUE, {
        "job_id": job_id,
        "findings": findings
    })


# ─────────────────────────────────────────────
# AGGREGATION COMPLETE
# ─────────────────────────────────────────────
def on_aggregation_complete(job_id, data, target):
    set_counter(job_id, "report", 1)

    push(MEMORY_QUEUE, {
        "job_id": job_id,
        "findings": data,
        "target": target
    })

    push(SCORING_QUEUE, {
        "job_id": job_id,
        "findings": data
    })

    db.update_job(job_id, status="reporting", progress=90)
    log(job_id, "[AGG] Attack graph + enrichment complete → Reporting")


# ─────────────────────────────────────────────
# REPORT COMPLETE
# ─────────────────────────────────────────────
def on_report_complete(job_id, report):
    db.save_report(job_id, report)

    db.update_job(job_id, status="done", progress=100)
    log(job_id, "[REPORT] Job complete")

    # cleanup Redis state
    r.delete(f"job:{job_id}:counts")
    r.delete(f"job:{job_id}:findings")
