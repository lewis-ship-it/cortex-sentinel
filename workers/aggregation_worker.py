
# workers/aggregation_worker.py

import json
from workers.base_worker import worker_loop, push_log
from task_queue.queues import AGGREGATION_QUEUE
from core.pipeline import on_aggregation_complete
from core.database import get_db  # ADDED: For persistent vault

from intelligence.attack_graph.engine import AttackGraph

graph_engine = AttackGraph()
db = get_db() # ADDED

def handle(job):
    job_id   = job["job_id"]
    raw      = job.get("findings", [])
    tier     = job.get("tier", "Basic")
    target   = job.get("target", "unknown_target")

    # Normalize: findings may arrive as a list (from exploit_worker) or
    # as a dict {findings, chains} (from api_worker).
    if isinstance(raw, dict):
        findings = raw.get("findings", [])
    elif isinstance(raw, list):
        findings = raw
    else:
        findings = []

    push_log(job_id, f"[AGG] Processing {len(findings)} findings in {tier} mode", tier=tier)

    push_log(job_id, "[AGG] Building attack graph & identifying chains", tier=tier)
    graph = graph_engine.build(findings)
    chains = graph_engine.find_attack_paths()

    enriched = {
        "findings": findings,
        "attack_graph": graph,
        "chains": chains
    }

    # FIXED: Use SQLite KV store instead of raw Redis for the Vault
    vault_key = f"vault:{job_id}"
    db.kv_set(vault_key, json.dumps(enriched))
    
    push_log(job_id, "[AGG] Full scan data archived in secure Vault.", tier=tier)

    on_aggregation_complete(job_id, enriched, target, tier=tier)

if __name__ == "__main__":
    worker_loop(AGGREGATION_QUEUE, handle)

