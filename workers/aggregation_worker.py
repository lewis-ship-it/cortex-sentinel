# workers/aggregation_worker.py

from workers.base_worker import worker_loop, push_log
from task_queue.queues import AGGREGATION_QUEUE
from core.pipeline import on_aggregation_complete

from intelligence.attack_graph.engine import AttackGraph

graph_engine = AttackGraph()


def handle(job):
    job_id = job["job_id"]
    findings = job["findings"]

    push_log(job_id, "[AGG] Building attack graph")

    graph = graph_engine.build(findings)
    chains = graph_engine.find_attack_paths()

    enriched = {
        "findings": findings,
        "attack_graph": graph,
        "chains": chains
    }

    push_log(job_id, "[AGG] Graph complete")

    on_aggregation_complete(job_id, enriched, "target")


if __name__ == "__main__":
    worker_loop(AGGREGATION_QUEUE, handle)