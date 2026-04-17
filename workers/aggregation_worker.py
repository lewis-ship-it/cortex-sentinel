# workers/aggregation_worker.py

import json
from workers.base_worker import worker_loop, push_log, r # r is now available from base
from task_queue.queues import AGGREGATION_QUEUE
from core.pipeline import on_aggregation_complete

from intelligence.attack_graph.engine import AttackGraph

graph_engine = AttackGraph()

def handle(job):
    job_id = job["job_id"]
    findings = job["findings"]
    tier = job.get("tier", "Basic") # Retrieve the tier set by base_worker fetch 
    target = job.get("target", "unknown_target")

    push_log(job_id, f"[AGG] Processing {len(findings)} findings in {tier} mode", tier=tier)

    # 1. Build the Attack Graph
    # We still build this for Basic users because the RiskPrioritizer 
    # uses 'chains' to calculate the "Anxiety Score" [cite: 1, 3]
    push_log(job_id, "[AGG] Building attack graph & identifying chains", tier=tier)
    graph = graph_engine.build(findings)
    chains = graph_engine.find_attack_paths()

    enriched = {
        "findings": findings,
        "attack_graph": graph,
        "chains": chains
    }

    # 2. THE VAULT: Instant Upsell Readiness
    # We store the full enriched data in Redis. If a Basic user clicks 'Upgrade',
    # we don't re-scan; we just pull this JSON and send it to the AI Report Generator.
    vault_key = f"vault:{job_id}"
    r.set(vault_key, json.dumps(enriched))
    r.expire(vault_key, 604800)  # Keep in vault for 7 days
    
    push_log(job_id, "[AGG] Full scan data archived in secure Vault.", tier=tier)

    # 3. Handoff to Pipeline
    # The pipeline will now use the tier to branch between Scorer and AI [cite: 2]
    on_aggregation_complete(job_id, enriched, target, tier=tier)

if __name__ == "__main__":
    worker_loop(AGGREGATION_QUEUE, handle)