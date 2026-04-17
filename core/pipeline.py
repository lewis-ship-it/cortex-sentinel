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
from intelligence.prioritization.risk_prioritizer import RiskPrioritizer

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

db = DatabaseManager()
prioritizer = RiskPrioritizer()


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
    """Scan finished - persist findings to Supabase and mark job as done"""
    
    
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    
    if findings:
        # 1. Store backup in Redis (for fast retrieval/logs)
        r.set(f"job:{job_id}:findings_json", json.dumps(findings))
        
        # 2. Persist to Supabase (so app.py can display them)
        try:
            log(job_id, f"[DB] Persisting {len(findings)} findings to database...")
            # We call the database manager to populate the vulnerabilities table
            db.save_vulnerabilities(job_id, findings) 
            log(job_id, "[DB] Persistence successful.")
        except Exception as e:
            # We log to Redis/Console so you can see exactly why the commit failed
            log(job_id, f"[DB] ERROR: Could not save findings: {str(e)}")
            print(f"!!! DB Persistence Error for {job_id}: {e}")

    # 3. Mark job complete ONLY after attempt to save data
    db.update_job(job_id, status="done", progress=100)
    log(job_id, f"[SCAN] Complete → {len(findings)} findings persisted → Job finished")


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
def on_aggregation_complete(job_id, data, target, tier="Basic"):
    """
    The Tiered Checkpoint: Branch logic between Free (Scoring) and Pro (AI Reporting)
    """
    # 1. THE VAULT: Always save the raw data to Redis/DB first.
    # If they upgrade later, we pull this exact JSON to run the AI report.
    r.set(f"job:{job_id}:vault:findings", json.dumps(data))
    log(job_id, "[VAULT] Raw scan findings archived.")

    # 2. TIER BRANCHING
    if tier == "Basic":
        log(job_id, "[PIPELINE] Basic Tier detected. Redirecting to Risk Prioritizer...")
        
        # Calculate the "Anxiety Score" using local lightweight logic
        # We pass findings and empty chains for basic mode
        prioritized_data = prioritizer.calculate(data.get("findings", []), [])
        
        # Create a "Redacted" report structure
        basic_report = {
            "target": target,
            "summary": {
                "total_findings": len(prioritized_data),
                "risk_score": max([f.get("priority_score", 0) for f in prioritized_data]) if prioritized_data else 0,
                "tier_status": "Basic (Free)"
            },
            "executive_content": {
                "summary": "UPGRADE TO PRO: Detailed AI analysis is locked.",
                "narrative": "UPGRADE TO PRO: Attack path chaining is locked.",
                "remediation": "UPGRADE TO PRO: Code-level fixes are locked."
            }
        }
        
        # Save the redacted report and end the job early
        db.save_report(job_id, basic_report)
        db.update_job(job_id, status="done", progress=100)
        log(job_id, "[REPORT] Basic scoring complete. Job finished.")
        
    else:
        # PRO TIER: Continue to the heavy AI Workers
        log(job_id, "[PIPELINE] Professional Tier detected. Engaging Cortex AI...")
        
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
        log(job_id, "[AGG] Enrichment complete → Triggering AI Report Worker")


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
