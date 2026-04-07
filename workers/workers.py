import sys
import os
import asyncio
import logging
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from task_queue.redis_scanner import dequeue_scan
from scanner.active_engine import ActiveScanner
from scanner.sast_engine import SASTScanner
from scanner.ai_report import AIReportGenerator
from core.database import DatabaseManager
from core.job_tracker import update_job
from scanner.risk_prioritizer import RiskPrioritizer
from scanner.attack_graph import AttackGraph
from scanner.exploit_engine import ExploitEngine

dast = ActiveScanner()
sast = SASTScanner()
db = DatabaseManager()
reporter = AIReportGenerator()
prioritizer = RiskPrioritizer()
graph_engine = AttackGraph()
exploit_engine = ExploitEngine()


def log_scan(job_id, data):
    with open("scan_logs.json", "a") as f:
        f.write(json.dumps({
            "job_id": job_id,
            "data": data
        }) + "\n")


def log(job_id, message):
    print(message)
    try:
        db.add_log(job_id, message)
    except Exception:
        pass


async def process(job):
    job_id = job["job_id"]
    url = job.get("url")
    zip_path = job.get("zip_path")
    auth = job.get("auth")

    try:
        log(job_id, f"🚀 Starting scan: {url or zip_path}")
        update_job(job_id, "running", 5)

        findings = []

        # -------------------------
        # DAST
        # -------------------------
        if url:
            log(job_id, "🌐 Crawling target...")
            results = await dast.scan(url, auth_config=auth)

            log(job_id, f"✅ DAST found {len(results)} issues")
            findings.extend(results)
            update_job(job_id, "running", 50)

        # -------------------------
        # SAST
        # -------------------------
        if zip_path and os.path.exists(zip_path):
            log(job_id, "📦 Running static analysis...")
            results = sast.scan_zip(zip_path)

            log(job_id, f"✅ SAST found {len(results)} issues")
            findings.extend(results)
            update_job(job_id, "running", 80)

        # -------------------------
        # SAVE RAW
        # -------------------------
        if findings:
            db.save_vulnerabilities(job_id, findings)

        # -------------------------
        # EXPLOIT VALIDATION (moved before report so report has verified data)
        # -------------------------
        logging.info("[*] Running Exploit Verification...")
        all_findings = await exploit_engine.verify(findings)

        # -------------------------
        # ATTACK GRAPH GENERATION
        # -------------------------
        graph = graph_engine.build(all_findings)
        attack_paths = graph_engine.find_attack_paths()
        for path in attack_paths:
            path["verified"] = any(
                step.get("exploit_verification", {}).get("verified")
                for step in path["path"]
            )

        # -------------------------
        # AI REPORT
        # -------------------------
        log(job_id, "🧠 Running AI analysis...")
        report = await reporter.generate_report(
            {
                "findings": all_findings,
                "attack_graph": graph,
                "chains": []
            },
            url or zip_path
        )

        chains = report.get("chains", [])

        prioritized = prioritizer.calculate(
            report.get("findings", []),
            chains
        )

        ai_chains = await reporter.brain.analyze_attack_chain(all_findings)
        report["ai_attack_chains"] = ai_chains

        report["prioritized"] = prioritized
        report["summary"]["top_risk"] = prioritized[0] if prioritized else None

        # Attach graph to report
        report["attack_graph"] = graph
        report["attack_paths"] = attack_paths

        db.save_report(job_id, report)

        # Log scan summary after we have all_findings defined
        log_scan(job_id, {
            "target": url,
            "findings": len(all_findings)
        })

        log(job_id, "🎉 Scan completed successfully")
        update_job(job_id, "done", 100)

    except Exception as e:
        log(job_id, f"❌ Error: {str(e)}")
        update_job(job_id, "failed", 100)


async def main():
    print("🚀 Worker running...")

    while True:
        job = dequeue_scan()
        if job:
            await process(job)

        await asyncio.sleep(1)


def start_worker_loop():
    """Entry point for threading from api/main.py"""
    asyncio.run(main())


if __name__ == "__main__":
    asyncio.run(main())