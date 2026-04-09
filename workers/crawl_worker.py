import asyncio
import logging

from task_queue.redis_client import pop, push, retry
from task_queue.queues import CRAWL_QUEUE, SCAN_QUEUE, BROWSER_QUEUE
from scanner.dast.smart_crawler import SmartCrawler
from core.orchestrator import Orchestrator

crawler = SmartCrawler()
orchestrator = Orchestrator()


async def main():
    logging.info("[CRAWL WORKER] Ready...")
    while True:
        job = pop(CRAWL_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue

        try:
            job_id = job["job_id"]
            url = job["url"]

            endpoints = await crawler.crawl(url)

            for ep in endpoints:
                push(SCAN_QUEUE, {"job_id": job_id, "url": ep})
                push(BROWSER_QUEUE, {"job_id": job_id, "url": ep})

            # 🔥 IMPORTANT
            await orchestrator.on_stage_complete(
                job_id,
                "crawl",
                {"endpoints": endpoints}
            )

        except Exception as e:
            retry(CRAWL_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())