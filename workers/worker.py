import sys
import os
import asyncio
import logging
import time

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
    job_id = job["job_id"]
    url = job.get("url")
    zip_path = job.get("zip_path")
    auth_config = job.get("auth")
    
    logging.info(f"[*] Starting Job {job_id} for {url or zip_path}")

    try:
        update_job(job_id, "running", 10)
        all_findings = []

        if url:
            logging.info(f"[*] Running DAST Engine on {url}...")
            dast_results = await dast_engine.scan(url, auth_config=auth_config)
            if dast_results:
                all_findings.extend(dast_results)
            update_job(job_id, "running", 50)

        if zip_path and os.path.exists(zip_path):
            logging.info(f"[*] Running SAST Engine on {zip_path}...")
            sast_results = sast_engine.scan_zip(zip_path)
            if sast_results:
                all_findings.extend(sast_results)
            update_job(job_id, "running", 80)

        if all_findings:
            db.save_vulnerabilities(job_id, all_findings)

        logging.info(f"[*] Intelligence Layer: Reasoning with Gemini AI...")
        report_content = await reporter.generate_report(all_findings, url or zip_path)
        db.save_report(job_id, report_content)
        
        update_job(job_id, "done", 100)
        logging.info(f"[+] Job {job_id} completed successfully.")

    except Exception as e:
        logging.error(f"[!] Critical Error in Worker: {e}")
        update_job(job_id, "failed", 100)

async def main():
    """Internal async loop to monitor Redis."""
    logging.info("🚀 Sentinel AI Worker is live. Monitoring Redis queue...")
    while True:
        try:
            job = dequeue_scan()
            if job:
                await process(job)
            await asyncio.sleep(1)
        except Exception as e:
            logging.error(f"Queue Error: {e}")
            await asyncio.sleep(5)

# --- THE FIX FOR main.py COMPATIBILITY ---
def start_worker_loop():
    """
    Bridge function: Allows the sync thread in main.py to 
    launch the async main() loop.
    """
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main())
    except Exception as e:
        logging.error(f"Fatal Worker Thread Error: {e}")

if __name__ == "__main__":
    start_worker_loop()