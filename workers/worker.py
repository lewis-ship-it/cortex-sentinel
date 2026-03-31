import sys
import os
import asyncio
import logging

# Ensure project root is in the python path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from task_queue.redis_scanner import dequeue_scan
from scanner.active_engine import ActiveScanner
from scanner.sast_engine import SASTScanner
from scanner.ai_report import AIReportGenerator
from core.database import DatabaseManager
from core.job_manager import update_job

# Initialize global system components
dast_engine = ActiveScanner()
sast_engine = SASTScanner()
db = DatabaseManager()
reporter = AIReportGenerator()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def process(job):
    """
    Main Orchestrator: Decides whether to run SAST or DAST, 
    then triggers the Gemini Reasoning Engine.
    """
    job_id = job["job_id"]
    url = job.get("url")
    zip_path = job.get("zip_path")
    auth_config = job.get("auth")
    
    logging.info(f"[*] Starting Job {job_id} for {url or zip_path}")

    try:
        # 1. Update status to started
        update_job(job_id, "running", 10)
        all_findings = []

        # 2. TRIGGER DAST (Dynamic Website Scanning)
        if url:
            logging.info(f"[*] Running DAST Engine on {url}...")
            dast_results = await dast_engine.scan(url, auth_config=auth_config)
            if dast_results:
                all_findings.extend(dast_results)
            update_job(job_id, "running", 50)

        # 3. TRIGGER SAST (Static Code/ZIP Scanning)
        if zip_path and os.path.exists(zip_path):
            logging.info(f"[*] Running SAST Engine on {zip_path}...")
            sast_results = sast_engine.scan_zip(zip_path)
            if sast_results:
                all_findings.extend(sast_results)
            update_job(job_id, "running", 80)

        # 4. SAVE RAW DATA
        if all_findings:
            db.save_vulnerabilities(job_id, all_findings)

        # 5. BRAIN PHASE: Gemini Reasoning & Exploit Generation
        logging.info(f"[*] Intelligence Layer: Reasoning with Gemini AI...")
        # Note: generate_report is now async to handle the Gemini API call
        report_content = await reporter.generate_report(all_findings, url or zip_path)
        
        # 6. SAVE FINAL REPORT
        db.save_report(job_id, report_content)
        
        update_job(job_id, "done", 100)
        logging.info(f"[+] Job {job_id} completed successfully.")

    except Exception as e:
        logging.error(f"[!] Critical Error in Worker: {e}")
        update_job(job_id, "failed", 100)

async def main():
    logging.info("🚀 Sentinel AI Worker is live. Monitoring Redis queue...")
    
    while True:
        try:
            # Pull the next job from Redis
            job = dequeue_scan()
            
            if job:
                await process(job)
            
            # Small sleep to prevent CPU spiking
            await asyncio.sleep(1)
            
        except Exception as e:
            logging.error(f"Queue Error: {e}")
            await asyncio.sleep(5)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Worker stopped by user.")