import asyncio
from task_queue.redis_client import push
from task_queue.queues import (
    CRAWL_QUEUE,
    SAST_QUEUE,
    NETWORK_QUEUE,
    MOBILE_QUEUE,
    SCAN_QUEUE,
    EXPLOIT_QUEUE,
    AGGREGATION_QUEUE,
    REPORT_QUEUE,
)

from core.state_manager import StateManager


class Orchestrator:
    def __init__(self):
        self.state = StateManager()

    async def start_job(self, job: dict):
        job_id = job["job_id"]
        scan_type = job.get("scan_type", "web")

        print(f"[Orchestrator] Starting job {job_id} ({scan_type})")

        # Initialize job state
        self.state.init_job(job_id, scan_type)

        if scan_type == "web":
            await self._start_web(job)

        elif scan_type == "network":
            await self._start_network(job)

        elif scan_type == "mobile":
            await self._start_mobile(job)

        else:
            raise ValueError(f"Unknown scan type: {scan_type}")

    async def _start_web(self, job):
        job_id = job["job_id"]

        push(CRAWL_QUEUE, job)

        if job.get("zip_path"):
            push(SAST_QUEUE, job)

    async def _start_network(self, job):
        push(NETWORK_QUEUE, job)

    async def _start_mobile(self, job):
        push(MOBILE_QUEUE, job)

    # 🔥 THIS IS THE MISSING PIECE
    async def on_stage_complete(self, job_id: str, stage: str, data=None):
        print(f"[Orchestrator] {job_id} completed stage: {stage}")

        self.state.mark_done(job_id, stage)

        # --- FLOW CONTROL ---

        if stage == "crawl":
            push(SCAN_QUEUE, {"job_id": job_id, "source": "crawl", "data": data})

        elif stage == "sast":
            push(SCAN_QUEUE, {"job_id": job_id, "source": "sast", "data": data})

        elif stage in ["scan"]:
            push(EXPLOIT_QUEUE, {"job_id": job_id, "data": data})

        elif stage == "exploit":
            push(AGGREGATION_QUEUE, {"job_id": job_id, "data": data})

        # --- FINAL COMPLETION CHECK ---
        if self.state.is_complete(job_id):
            print(f"[Orchestrator] Job {job_id} COMPLETE → generating report")
            push(REPORT_QUEUE, {"job_id": job_id})