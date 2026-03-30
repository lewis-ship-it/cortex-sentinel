import asyncio
from queue.redis_queue import dequeue_scan
from scanner.active_engine import ActiveScanner
from core.database import DatabaseManager
from core.job_manager import update_job

scanner = ActiveScanner()
db = DatabaseManager()

async def process(job):
    job_id = job["job_id"]
    url = job["url"]

    update_job(job_id, "running", 10)

    results = await scanner.scan(url)

    update_job(job_id, "running", 90)

    db.save_vulnerabilities(job_id, results)

    update_job(job_id, "done", 100)

def run():
    print("🚀 Worker started")
    while True:
        job = dequeue_scan()
        asyncio.run(process(job))

if __name__ == "__main__":
    run()