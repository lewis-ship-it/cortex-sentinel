import asyncio
from task_queue.redis_client import push
from task_queue.queues import *

class Orchestrator:

    async def start_job(self, job):
        url = job.get("url")
        zip_path = job.get("zip_path")

        # Step 1: Crawl
        push(CRAWL_QUEUE, {"job_id": job["job_id"], "url": url})

        # Step 2: SAST if zip
        if zip_path:
            push(SAST_QUEUE, job)