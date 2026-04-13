# core/orchestrator.py
from task_queue.redis_client import push
from task_queue.queues import CRAWL_QUEUE, SCAN_QUEUE, EXPLOIT_QUEUE, AGGREGATION_QUEUE, REPORT_QUEUE

class Orchestrator:
    async def on_stage_complete(self, job_id, stage, data=None):
        print(f"[Orchestrator] {job_id} completed stage: {stage}")
        
        # Ensure data structure is consistent
        data = data or {"findings": [], "urls": []}

        # 1. NEW: Handle Crawl -> Scan transition
        if stage == "crawl":
            urls_to_scan = data.get("urls", [])
            if not urls_to_scan:
                print(f"[Orchestrator] {job_id} Crawl finished with 0 URLs. Skipping scan.")
                # Directly jump to report or end
                return 

            # Centralized Routing: Push the found URLs into the Scan Queue
            push(SCAN_QUEUE, {
                "job_id": job_id,
                "urls": urls_to_scan, # Pass the list of discovered pages
                "data": data
            })

        # 2. Handle Scan -> Exploit
        elif stage == "scan":
            push(EXPLOIT_QUEUE, {
                "job_id": job_id,
                "data": data
            })

        # 3. Handle Exploit -> Aggregation
        elif stage == "exploit":
            push(AGGREGATION_QUEUE, {
                "job_id": job_id,
                "data": data
            })

        # 4. Handle Aggregation -> Report
        elif stage == "aggregation":
            push(REPORT_QUEUE, {
                "job_id": job_id,
                "data": data
            })