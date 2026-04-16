# workers/scoring_worker.py

from workers.base_worker import worker_loop, push_log
from task_queue.queues import SCORING_QUEUE
from core.pipeline import on_report_complete


def score(findings):
    score = 100

    for f in findings:
        if f["severity"] == "Critical":
            score -= 20
        elif f["severity"] == "High":
            score -= 10
        elif f["severity"] == "Medium":
            score -= 5

    return max(score, 0)


def handle(job):
    job_id = job["job_id"]
    findings = job["findings"]

    push_log(job_id, "[SCORING] Calculating risk score")

    final_score = score(findings)

    report = {
        "score": final_score,
        "findings": findings
    }

    push_log(job_id, f"[SCORING] Score = {final_score}")

    on_report_complete(job_id, report)


if __name__ == "__main__":
    worker_loop(SCORING_QUEUE, handle)