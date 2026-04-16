# workers/report_worker.py

from workers.base_worker import worker_loop, push_log
from task_queue.queues import REPORT_QUEUE
from core.pipeline import on_report_complete

from scanner.ai_report import AIReportGenerator

reporter = AIReportGenerator()


def handle(job):
    job_id = job["job_id"]
    data = job["findings"]
    target = job.get("target", "unknown")

    push_log(job_id, "[REPORT] Generating report")

    import asyncio
    report = asyncio.run(
        reporter.generate_report(data, target)
    )

    push_log(job_id, "[REPORT] Done")

    on_report_complete(job_id, report)


if __name__ == "__main__":
    worker_loop(REPORT_QUEUE, handle)