# workers/crawl_workers.py

import asyncio
import logging

from task_queue.redis_client import pop, push, retry
from task_queue.queues import CRAWL_QUEUE, SCAN_QUEUE, BROWSER_QUEUE
from scanner.smart_crawler import SmartCrawler
from core.job_tracker import update_stage

crawler = SmartCrawler()


async def main():
    logging.info("[CRAWL WORKER] Ready and listening...")

    while True:
        job = pop(CRAWL_QUEUE)

        if not job:
            await asyncio.sleep(1)
            continue

        try:
            job_id = job["job_id"]
            url    = job["url"]

            update_stage(job_id, "crawling", 10)

            endpoints = await crawler.crawl(url)

            logging.info(f"[CRAWL] Found {len(endpoints)} endpoints")

            for ep in endpoints:
                push(SCAN_QUEUE,    {"job_id": job_id, "url": ep})
                push(BROWSER_QUEUE, {"job_id": job_id, "url": ep})

        except Exception as e:
            retry(CRAWL_QUEUE, job, str(e))


asyncio.run(main())