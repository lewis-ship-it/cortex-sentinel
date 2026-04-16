import sys
import os
import asyncio
import logging

# Ensure root directory is in path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from task_queue.redis_scanner import dequeue_scan
from scanner.dast.active_scanner import ActiveScanner
from scanner.sast_engine import SASTScanner
from scanner.ai_report import AIReportGenerator
from intelligence.ai_brain import AIBrain
from core.database import DatabaseManager
from core.job_tracker import update_job
from intelligence.prioritization.risk_prioritizer import RiskPrioritizer
from intelligence.attack_graph.engine import AttackGraph
from scanner.exploit.exploit_engine import ExploitEngine

# Static Engines
logger         = logging.getLogger(__name__)
sast           = SASTScanner()
reporter       = AIReportGenerator()
brain          = AIBrain()
prioritizer    = RiskPrioritizer()
graph_engine   = AttackGraph()
exploit_engine = ExploitEngine()
db             = DatabaseManager()

def log(job_id: str, message: str):
    print(f"[{job_id}] {message}")
    try:
        # Safety check for DatabaseManager attribute 'db'
        if hasattr(db, 'db') and db.db:
            db.add_log(job_id, message)
    except Exception:
        pass

async def process(job):
    job_id   = job["job_id"]
    # Logic: Use 'target_url' to match your Supabase column name
    target_url = job.get("target_url") or job.get("url") 
    zip_path   = job.get("zip_path")
    auth       = job.get("auth")
    budget     = job.get("budget", 2.00)

    # Prevent crash if DatabaseManager failed to init
    if not hasattr(db, 'db') or db.db is None:
        print(f"[{job_id}] CRITICAL: Database connection missing. Skipping job.")
        return

    # Initialize per-job instances
    dast = ActiveScanner(job_id=job_id, budget=budget)
    dast.db = db
    findings = []

    try:
        log(job_id, f"Cortex Sentinel starting scan: {target_url or zip_path}")
        update_job(job_id, status="running", progress=5)

        # 1. Web Scanning (DAST)
        if target_url:
            log(job_id, "Running DAST Engine...")
            # We pass the target_url here to the scanner
            results = await dast.scan(target_url, auth_config=auth, job_id=job_id)
            findings.extend(results)
            await dast.finalize_and_report() 
            update_job(job_id, status="running", progress=40)

        # 2. Source Code Scanning (SAST)
        if zip_path and os.path.exists(zip_path):
            log(job_id, "Running SAST Engine...")
            s_results = sast.scan_zip(zip_path)
            findings.extend(s_results)
            update_job(job_id, status="running", progress=60)

        # 3. Intelligence Phase
        if findings:
            log(job_id, "Analyzing findings and building attack graph...")
            db.save_vulnerabilities(job_id, findings)
            
            all_findings = await exploit_engine.verify(findings)
            graph = graph_engine.build(all_findings)
            attack_paths = graph_engine.find_attack_paths()

            prioritized = prioritizer.calculate(all_findings, [])
            ai_chains = await brain.analyze_attack_chain(all_findings)

            # 4. Final Report
            log(job_id, "Generating final report...")
            report_data = {
                "findings":         all_findings,
                "prioritized":      prioritized,
                "ai_attack_chains": ai_chains,
                "attack_graph":     graph,
                "attack_paths":     attack_paths,
                "summary": {
                    "top_risk":    prioritized[0] if prioritized else None,
                    "total_vulns": len(all_findings)
                }
            }
            
            # Using target_url for the report metadata
            full_report = await reporter.generate_report(report_data, target_url or zip_path)
            db.save_report(job_id, full_report)
        
        update_job(job_id, status="done", progress=100)
        log(job_id, "Scan completed successfully.")

    except Exception as e:
        log(job_id, f"CRITICAL FAILURE: {str(e)}")
        update_job(job_id, status="failed", progress=100)
        try:
            await dast.finalize_and_report()
        except:
            pass

async def main():
    print("Sentinel Worker Online — listening to Redis...")
    while True:
        try:
            job = dequeue_scan()
            if job:
                await process(job)
        except Exception as e:
            print(f"Queue Error: {e}")
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())