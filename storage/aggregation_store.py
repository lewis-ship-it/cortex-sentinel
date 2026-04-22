# storage/aggregation_store.py
# ──────────────────────────────────────────────────────────────────────────────
# SQLite-backed aggregation store — drop-in replacement for the Redis version.
# Uses the kv_store table via the _RedisShim.
# ──────────────────────────────────────────────────────────────────────────────

import json
from task_queue.redis_client import kv_set, kv_get, kv_delete


def add_findings(job_id: str, findings: list) -> None:
    key      = f"agg:{job_id}"
    existing = json.loads(kv_get(key) or "[]")
    existing.extend(findings)

    # Deduplicate by (type, url, payload prefix)
    seen, unique = set(), []
    for f in existing:
        k = f"{f.get('type')}::{f.get('url')}::{str(f.get('payload',''))[:30]}"
        if k not in seen:
            seen.add(k)
            unique.append(f)

    kv_set(key, json.dumps(unique))


def get_findings(job_id: str) -> list:
    raw = kv_get(f"agg:{job_id}")
    return json.loads(raw) if raw else []


def clear(job_id: str) -> None:
    kv_delete(f"agg:{job_id}")