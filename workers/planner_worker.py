from workers.base_worker import worker_loop, push_log
from task_queue.queues import PLANNER_QUEUE, SCAN_QUEUE
from task_queue.redis_client import push


def handle(job):
    job_id = job["job_id"]
    findings = job["findings"]

    push_log(job_id, "[PLANNER] Running")

    for f in findings:
        url = f.get("target_url")

        if not url or url == "N/A":
            continue

        if "id=" in url:
            for i in range(1, 5):
                push(SCAN_QUEUE, {
                    "job_id": job_id,
                    "target_url": url.replace("id=1", f"id={i}")
                })


if __name__ == "__main__":
    worker_loop(PLANNER_QUEUE, handle)