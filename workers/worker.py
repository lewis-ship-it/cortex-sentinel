import sys
import os
import asyncio
import logging
import json

# Ensure project root is in the python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from task_queue.redis_scanner import dequeue_scan
from scanner.active_engine import ActiveScanner
from scanner.sast_engine import SASTScanner
from scanner.ai_report import AIReportGenerator
from core.database import DatabaseManager
from core.job_manager import update_job

# Initialize components
dast_engine = ActiveScanner()
sast_engine = SASTScanner()
db = DatabaseManager()
reporter = AIReportGenerator()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def process(job):
    job_id = job["job_id"]
    url = job.get("url")
    zip_path = job.get("zip_path")
    
    logging.info(f"[*] Starting Job {job_id}")

    try:
        # STEP 1: Initialization
        update_job(job_id, "Initializing Sentinel Engines...", 10)
        all_findings = []

        # STEP 2: DAST Phase
        if url:
            update_job(job_id, f"Crawling & Testing: {url}", 30)
            dast_results = await dast_engine.scan(url)
            if dast_results:
                all_findings.extend(dast_results)
        
        # STEP 3: SAST Phase
        if zip_path:
            update_job(job_id, "Analyzing Source Code Security...", 60)
            sast_results = sast_engine.scan_zip(zip_path)
            if sast_results:
                all_findings.extend(sast_results)

        # STEP 4: AI Reasoning
        update_job(job_id, "Gemini AI: Analyzing vulnerabilities...", 85)
        if all_findings:
            db.save_vulnerabilities(job_id, all_findings)
            report_content = await reporter.generate_report(all_findings, url or zip_path)
            db.save_report(job_id, report_content)
        
        # STEP 5: Finalize
        update_job(job_id, "Audit Complete", 100)
        logging.info(f"[+] Job {job_id} complete.")

    except Exception as e:
        logging.error(f"[!] Job {job_id} failed: {e}")
        update_job(job_id, f"Failed: {str(e)}", 0)

async def main_loop():
    logging.info("🚀 Sentinel AI Worker monitoring queue...")
    while True:
        try:
            job = dequeue_scan()
            if job:
                # Ensure job is a dict (handles string-to-dict conversion)
                job_data = json.loads(job) if isinstance(job, str) else job
                await process(job_data)
            await asyncio.sleep(1)
        except Exception as e:
            logging.error(f"Loop Error: {e}")
            await asyncio.sleep(5)

def start_worker_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main_loop())