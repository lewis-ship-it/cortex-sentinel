# workers/report_worker.py
import asyncio
import logging
from task_queue.redis_client import pop, retry
from task_queue.queues import REPORT_QUEUE
from intelligence.ai.report_generator import AIReportGenerator
from intelligence.attack_graph.engine import AttackGraph
from intelligence.prioritization.risk_prioritizer import RiskPrioritizer # NEW IMPORT
from storage.database import DatabaseManager
from storage.aggregation_store import clear
from core.orchestrator import Orchestrator

logger = logging.getLogger(__name__)
ai = AIReportGenerator()
db = DatabaseManager()
graph_engine = AttackGraph()
prioritizer = RiskPrioritizer() # INITIALIZE PRIORITIZER
orchestrator = Orchestrator()

async def main():
    logging.basicConfig(level=logging.INFO)
    logger.info("[REPORT WORKER] Production Reporting Engine Active...")
    
    while True:
        job = pop(REPORT_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue
            
        job_id = job.get("job_id")
        findings = job.get("findings", [])
        
        try:
            # 1. Build Attack Graph and find chains
            graph = graph_engine.build(findings)
            attack_paths = graph_engine.find_attack_paths()
            
            # 2. THE FIX: Prioritize findings before sending to AI
            # This adds the 'priority_score' and 'fix_first' flags to the data
            prioritized_findings = prioritizer.calculate(findings, attack_paths)
            
            # 3. Generate the AI report with prioritized data
            report = await ai.generate_report(
                {
                    "findings": prioritized_findings, 
                    "attack_graph": graph, 
                    "chains": attack_paths
                },
                job_id,
            )
            
            # 4. Save and Cleanup
            db.save_report(job_id, report)
            clear(job_id)
            db.update_job(job_id, status="done", progress=100)
            
            logger.info(f"[REPORT WORKER] Successfully generated prioritized report for: {job_id}")
            
        except Exception as e:
            logger.error(f"[REPORT WORKER] Critical failure in reporting pipeline: {e}")
            retry(REPORT_QUEUE, job, str(e))

if __name__ == "__main__":
    asyncio.run(main())