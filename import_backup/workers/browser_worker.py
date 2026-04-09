# workers/browser_workers.py

import asyncio

from task_queue.redis_client import pop, push, retry
from task_queue.queues import BROWSER_QUEUE, AGGREGATION_QUEUE
from scanner.playwright_engine import PlaywrightScanner

browser = PlaywrightScanner()


async def main():
    while True:
        job = pop(BROWSER_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue

        try:
            findings, _ = await browser.scan(job["url"])
            push(AGGREGATION_QUEUE, {
                "job_id":   job["job_id"],
                "findings": findings,
            })
        except Exception as e:
            retry(BROWSER_QUEUE, job, str(e))


if __name__ == "__main__":
    asyncio.run(main())
