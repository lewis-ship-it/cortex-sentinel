import sys
import os
import asyncio
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from task_queue.redis_scanner import dequeue_scan
from scanner.active_engine import ActiveScanner
from core.database import DatabaseManager
from core.job_manager import update_job
from scanner.ai_report import AIReportGenerator

scanner = ActiveScanner()
db = DatabaseManager()
reporter = AIReportGenerator()
report = reporter.generate_report(results, url)
db.save_report(job_id, report)

async def process(job):
    job_id = job["job_id"]
    url = job["url"]
    print(f"[*] Processing: {url} (ID: {job_id})")

    update_job(job_id, "running", 10)
    results = await scanner.scan(
    url,
    auth_config=job.get("auth")
  )
    
    update_job(job_id, "running", 90)
    db.save_vulnerabilities(job_id, results)
    update_job(job_id, "done", 100)
    print(f"[+] Finished: {job_id}")

def run():
    print("🚀 Worker started and listening...")
    while True:
        job = dequeue_scan()
        if job:
            asyncio.run(process(job))

if __name__ == "__main__":
    run()