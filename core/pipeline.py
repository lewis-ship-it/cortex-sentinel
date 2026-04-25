# core/pipeline.py
# ──────────────────────────────────────────────────────────────────────────────
# Pipeline orchestration — STRICT SQLite edition.
# All legacy state_manager calls removed to prevent dual-write conflicts.
# All ephemeral caching (r.set) moved to db.kv_set for persistence.
#
# FIXES vs previous version:
#   1. Removed BROWSER_QUEUE push — no browser_worker exists, so those jobs
#      would queue forever and the counter would never reach zero, stalling
#      the pipeline at "scanning" indefinitely.
#   2. Added safety: if scan counter is stuck at 0 for too long, force
#      transition to exploit stage.
# ──────────────────────────────────────────────────────────────────────────────
import time
import json
from typing import Optional, Dict, List, Any

from task_queue.redis_client import push
from task_queue.queues import (
    SCAN_QUEUE, EXPLOIT_QUEUE, AGGREGATION_QUEUE,
    REPORT_QUEUE, PLANNER_QUEUE, MEMORY_QUEUE, SCORING_QUEUE,
)
from core.counters import set_counter, decrement, get_counter
from core.database import get_db
from core.logger import get_logger
from intelligence.prioritization.risk_prioritizer import RiskPrioritizer

db           = get_db()
prioritizer  = RiskPrioritizer()
logger       = get_logger("pipeline")


def on_scan_complete(
    job_id:   str,
    findings: List[Dict],
    target:   Optional[str] = None,
    tier:     str = "Basic",
) -> None:
    try:
        # Accumulate findings from multiple scan workers
        if findings:
            try:
                raw = db.kv_get(f"job:{job_id}:findings_json")
                all_findings = json.loads(raw) if raw else []
            except Exception:
                logger.error("Corrupted findings JSON — resetting", job_id)
                all_findings = []

            accumulated = json.loads(raw) if raw else []
            accumulated.extend(findings)
            db.kv_set(f"job:{job_id}:findings_json", json.dumps(accumulated))
            logger.info(
                f"Scan result received — +{len(findings)} findings "
                f"(total accumulated: {len(accumulated)})",
                job_id,
            )
        start_key = f"job:{job_id}:scan_start"

        if not db.kv_get(start_key):
            db.kv_set(start_key, str(time.time()))
        remaining = decrement(job_id, "scan")
        logger.info(f"Pending scan slots remaining: {remaining}", job_id)

        # 🔥 FAILSAFE: if counter is broken or stuck, force progress
        if remaining > 0:
            start_time = float(db.kv_get(start_key) or 0)

            if time.time() - start_time > 120:  # 2 min timeout
                logger.warning("Scan stage timeout — forcing completion", job_id)
            else:
                return

        # All scans done — route to exploit
        raw = db.kv_get(f"job:{job_id}:findings_json")
        all_findings = json.loads(raw) if raw else []

        db.update_job(job_id, status="exploiting", progress=55)

        logger.info(
            f"All URLs scanned — routing {len(all_findings)} total findings to exploit",
            job_id,
            details={"finding_count": len(all_findings), "tier": tier},
        )

        push(EXPLOIT_QUEUE, {
            "job_id":   job_id,
            "findings": all_findings,
            "tier":     tier,
            "target":   target or "unknown",
        })

    except Exception as e:
        logger.error(f"on_scan_complete failed: {e}", job_id)
        db.update_job(job_id, status="failed", progress=100)


def on_exploit_complete(
    job_id:   str,
    findings: List[Dict],
    tier:     str = "Basic",
) -> None:
    try:
        if findings:
            db.kv_set(f"job:{job_id}:exploit_results", json.dumps(findings))

        db.update_job(job_id, status="aggregating", progress=65)

        if tier == "Professional":
            push(PLANNER_QUEUE, {"job_id": job_id, "findings": findings})

        push(AGGREGATION_QUEUE, {
            "job_id":   job_id,
            "findings": findings,
            "tier":     tier,
        })

    except Exception as e:
        logger.error(f"on_exploit_complete failed: {e}", job_id)
        db.update_job(job_id, status="failed", progress=100)


def on_aggregation_complete(
    job_id: str,
    data:   Dict[str, Any],
    target: str = "unknown",
    tier:   str = "Basic",
) -> None:
    try:
        db.kv_set(f"job:{job_id}:vault:findings", json.dumps(data))

        if tier == "Basic":
            findings         = data.get("findings", [])
            prioritized_data = prioritizer.calculate(findings, [])

            basic_report = {
                "target":  target,
                "summary": {
                    "total_findings": len(prioritized_data),
                    "risk_score":     max(
                        (f.get("priority_score", 0) for f in prioritized_data), default=0
                    ),
                    "tier_status":    "Basic (Free) — Limited Analysis",
                },
                "executive_summary": "Upgrade to Professional for full AI analysis.",
                "findings":          prioritized_data,
            }

            db.save_report(job_id, basic_report)
            db.update_job(job_id, status="done", progress=100)
            logger.info("Basic tier job complete", job_id, tier="Basic")

        else:
            db.update_job(job_id, status="memory_enriching", progress=70)

            push(MEMORY_QUEUE, {"job_id": job_id, "findings": data, "target": target, "tier": tier})
            push(SCORING_QUEUE, {"job_id": job_id, "findings": data, "tier": tier})
            push(REPORT_QUEUE, {
                "job_id":    job_id,
                "findings":  data,
                "target":    target,
                "tier":      tier,
            })
            logger.info("Professional tier — routed to memory + scoring + AI report", job_id, tier="Professional")

    except Exception as e:
        logger.error(f"on_aggregation_complete failed: {e}", job_id)
        db.update_job(job_id, status="failed", progress=100)


def on_report_complete(
    job_id: str,
    report: Dict[str, Any],
    tier:   str = "Professional",
) -> None:
    try:
        db.save_report(job_id, report)
        db.update_job(job_id, status="done", progress=100)

        db.kv_delete(f"job:{job_id}:counts")

        logger.info("Job successfully completed", job_id, tier=tier)

    except Exception as e:
        logger.error(f"on_report_complete failed: {e}", job_id)
        db.update_job(job_id, status="failed", progress=100)


def on_crawl_complete(
    job_id: str,
    urls:   List[str],
    auth:   Optional[Dict] = None,
    tier:   str = "Basic",
) -> None:
    try:
        if not urls:
            logger.warning("Crawl complete but no URLs", job_id)
            db.update_job(job_id, status="failed", progress=100)
            db.add_log(job_id, "[SYSTEM] No URLs discovered during crawl", level="ERROR")
            return

        # FIX: Only push to SCAN_QUEUE, NOT BROWSER_QUEUE.
        # No browser_worker exists, so BROWSER_QUEUE jobs would never be
        # consumed, and the counter would never reach zero.
        unique_urls = list(set(urls))

        set_counter(job_id, "scan", len(unique_urls))
        db.update_job(job_id, status="scanning", progress=25)

        for url in unique_urls:
            push(SCAN_QUEUE, {
                "job_id": job_id,
                "url": url,
                "auth": auth,
                "tier": tier
            })


        logger.info(
            f"Crawl complete — {len(unique_urls)} URLs queued for scanning",
            job_id,
            details={"url_count": len(unique_urls)},
        )

    except Exception as e:
        logger.error(f"on_crawl_complete failed: {e}", job_id)
        db.update_job(job_id, status="failed", progress=100)
