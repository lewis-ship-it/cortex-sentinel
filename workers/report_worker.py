# workers/report_worker.py

import asyncio
from workers.base_worker import worker_loop, push_log
from task_queue.queues import REPORT_QUEUE
from core.pipeline import on_report_complete
from scanner.ai_report import AIReportGenerator

reporter = AIReportGenerator()

async def generate_tiered_report(job_id, data, target, tier):
    """
    Orchestrates the AI generation process.
    """
    # FINAL SAFETY GATE: Double check that Basic users don't trigger AI.
    if tier == "Basic":
        push_log(job_id, "[REPORT] Error: AI Report triggered for Basic tier. Diverting to Scorer.", tier=tier)
        # Fallback: Return a structured error so the pipeline can recover
        return {"error": "AI Report requires Professional tier."}

    push_log(job_id, f"[REPORT] AI Brain synthesizing report for {target}...", tier=tier)
    
    # This calls the actual LLM logic (Qwen/Gemini)
    report = await reporter.generate_report(data, target, tier=tier)
    
    return report

def handle(job):
    job_id = job["job_id"]
    data = job["findings"]
    target = job.get("target", "unknown")
    tier = job.get("tier", "Basic")

    # Run the async generation
    report = asyncio.run(generate_tiered_report(job_id, data, target, tier))

    push_log(job_id, "[REPORT] Generation complete.", tier=tier)
    on_report_complete(job_id, report)

if __name__ == "__main__":
    worker_loop(REPORT_QUEUE, handle)