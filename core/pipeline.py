# core/pipeline.py
# ──────────────────────────────────────────────────────────────────────────────
# Pipeline orchestration — STRICT SQLite edition.
# All legacy state_manager calls removed to prevent dual-write conflicts.
# All ephemeral caching (r.set) moved to db.kv_set for persistence.
# ──────────────────────────────────────────────────────────────────────────────

import json
from typing import Optional, Dict, List, Any

from task_queue.redis_client import push
from task_queue.queues import (
    SCAN_QUEUE, BROWSER_QUEUE, EXPLOIT_QUEUE, AGGREGATION_QUEUE,
    REPORT_QUEUE, PLANNER_QUEUE, MEMORY_QUEUE, SCORING_QUEUE,
)
from core.counters import set_counter, decrement
from core.database import get_db
from core.logger import get_logger
from intelligence.prioritization.risk_prioritizer import RiskPrioritizer

db           = get_db()
prioritizer  = RiskPrioritizer()
logger       = get_logger("pipeline")


# ─────────────────────────────────────────────────────────────────────────────
# SCAN COMPLETE → EXPLOIT
# ─────────────────────────────────────────────────────────────────────────────

def on_scan_complete(
    job_id:   str,
    findings: List[Dict],
    target:   Optional[str] = None,
    tier:     str = "Basic",
) -> None:
    try:
        if not findings:
            logger.warning(f"Scan complete but no findings", job_id)
            db.update_job(job_id, status="exploiting", progress=55)
            push(EXPLOIT_QUEUE, {"job_id": job_id, "findings": [], "tier": tier})
            return

        # Cache findings in SQLite KV store instead of raw Redis
        db.kv_set(f"job:{job_id}:findings_json", json.dumps(findings))

        db.update_job(job_id, status="exploiting", progress=55)

        logger.info(
            f"Scan complete — routing {len(findings)} findings to exploit",
            job_id,
            details={"finding_count": len(findings), "tier": tier},
        )

        push(EXPLOIT_QUEUE, {
            "job_id":   job_id,
            "findings": findings,
            "tier":     tier,
            "target":   target or "unknown",
        })

    except Exception as e:
        logger.error(f"on_scan_complete failed: {e}", job_id)
        db.update_job(job_id, status="failed", progress=100)


# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT COMPLETE → AGGREGATION
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# AGGREGATION COMPLETE → TIERED ROUTING
# ─────────────────────────────────────────────────────────────────────────────

def on_aggregation_complete(
    job_id: str,
    data:   Dict[str, Any],
    target: str = "unknown",
    tier:   str = "Basic",
) -> None:
    try:
        # Archive raw findings in SQLite KV store (Survives restarts)
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
            # Professional tier: memory enrichment + scoring + AI report
            db.update_job(job_id, status="memory_enriching", progress=70)

            push(MEMORY_QUEUE, {"job_id": job_id, "findings": data, "target": target, "tier": tier})
            push(SCORING_QUEUE, {"job_id": job_id, "findings": data, "tier": tier})
            # FIX: Also push to REPORT_QUEUE for AI-powered narrative generation.
            # Previously Professional tier never triggered report_worker — only scoring_worker
            # called on_report_complete, which skips the AI analysis.
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


# ─────────────────────────────────────────────────────────────────────────────
# REPORT COMPLETE → DONE
# ─────────────────────────────────────────────────────────────────────────────

def on_report_complete(
    job_id: str,
    report: Dict[str, Any],
    tier:   str = "Professional",
) -> None:
    try:
        db.save_report(job_id, report)
        db.update_job(job_id, status="done", progress=100)

        # Clean up ephemeral state from SQLite KV
        db.kv_delete(f"job:{job_id}:counts")

        logger.info("Job successfully completed", job_id, tier=tier)

    except Exception as e:
        logger.error(f"on_report_complete failed: {e}", job_id)
        db.update_job(job_id, status="failed", progress=100)


# ─────────────────────────────────────────────────────────────────────────────
# CRAWL COMPLETE → SCAN
# ─────────────────────────────────────────────────────────────────────────────

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

        set_counter(job_id, "scan", len(urls))
        db.update_job(job_id, status="scanning", progress=25)

        for url in urls:
            push(SCAN_QUEUE,    {"job_id": job_id, "url": url, "auth": auth, "tier": tier})
            push(BROWSER_QUEUE, {"job_id": job_id, "url": url, "auth": auth, "tier": tier})

        logger.info(
            f"Crawl complete — {len(urls)} URLs queued",
            job_id,
            details={"url_count": len(urls)},
        )

    except Exception as e:
        logger.error(f"on_crawl_complete failed: {e}", job_id)
        db.update_job(job_id, status="failed", progress=100)