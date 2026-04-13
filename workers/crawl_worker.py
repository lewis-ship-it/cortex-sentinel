# workers/crawl_worker.py
import asyncio
import logging
import httpx
from task_queue.redis_client import pop, push, retry
from task_queue.queues import CRAWL_QUEUE, SCAN_QUEUE
from scanner.dast.crawler import Crawler
from core.orchestrator import Orchestrator
from core.logger import log_event, set_stage

logger = logging.getLogger(__name__)
orchestrator = Orchestrator()

async def process_job(job):
    job_id = job.get("job_id")
    url = job.get("url")
    auth = job.get("auth")

    # Set UI state to 'crawl'
    set_stage(job_id, "crawl")
    log_event(job_id, "crawl", f"🕸️ Starting crawl on {url}")

    try:
        async with httpx.AsyncClient(
            verify=False, 
            follow_redirects=True, 
            timeout=20
        ) as client:
            crawler = Crawler(url)
            # Perform the actual crawling logic
            endpoints, forms = await crawler.crawl(client)

        logger.info(f"[CRAWL WORKER] {len(endpoints)} endpoints found for {job_id}")
        log_event(job_id, "crawl", f"Found {len(endpoints)} unique endpoints and {len(forms)} forms.")

        # Handoff to orchestrator to handle the routing to SCAN_QUEUE
        await orchestrator.on_stage_complete(job_id, "crawl", {
            "urls": list(endpoints), 
            "forms": forms,
            "auth": auth
        })

    except Exception as e:
        logger.error(f"[CRAWL WORKER] Error: {e}")
        log_event(job_id, "crawl", f"Error during crawl: {str(e)}")
        # Re-queue the job if it fails
        retry(CRAWL_QUEUE, job, str(e))

async def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger.info("[CRAWL WORKER] Ready and listening for jobs...")

    while True:
        job = pop(CRAWL_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue
            
        await process_job(job)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Stopping Crawl Worker...")