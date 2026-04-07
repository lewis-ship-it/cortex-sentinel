import asyncio
from task_queue.redis_client import push

from task_queue.queues import (
    CRAWL_QUEUE,
    SAST_QUEUE,
    NETWORK_QUEUE,
    MOBILE_QUEUE,
    AGGREGATION_QUEUE,
)

class Orchestrator:

    async def start_job(self, job):
        job_id = job["job_id"]

        url = job.get("url")
        zip_path = job.get("zip_path")
        scan_type = job.get("scan_type", "web")  # web, network, mobile

        print(f"[Orchestrator] Starting job {job_id} ({scan_type})")

        # Route based on scan type
        if scan_type == "web":
            await self._start_web(job_id, url, zip_path)

        elif scan_type == "network":
            await self._start_network(job_id, job)

        elif scan_type == "mobile":
            await self._start_mobile(job_id, job)

        else:
            raise ValueError(f"Unknown scan type: {scan_type}")

    async def _start_web(self, job_id, url, zip_path):
        push(CRAWL_QUEUE, {"job_id": job_id, "url": url})

        if zip_path:
            push(SAST_QUEUE, {"job_id": job_id, "zip_path": zip_path})

    async def _start_network(self, job_id, job):
        push(NETWORK_QUEUE, {
            "job_id": job_id,
            "target": job.get("target")
        })

    async def _start_mobile(self, job_id, job):
        push(MOBILE_QUEUE, {
            "job_id": job_id,
            "apk_path": job.get("apk_path")
        })