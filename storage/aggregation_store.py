# storage/aggregation_store.py
import os
import json
import redis

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Initialize Redis Connection
try:
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
except Exception:
    r = None

def add_findings(job_id: str, findings: list):
    """
    Appends new findings to the aggregation bucket for a job.
    Includes deduplication and a 24-hour expiration.
    """
    if r is None:
        return

    key = f"agg:{job_id}"
    
    # 1. Retrieve existing findings
    existing_data = r.get(key)
    data = json.loads(existing_data) if existing_data else []
    
    # 2. Merge new findings
    data.extend(findings)
    
    # 3. Deduplicate based on type, url, and a snippet of the payload
    seen, unique = set(), []
    for f in data:
        # Create a unique signature for each finding
        k = f"{f.get('type')}::{f.get('url')}::{f.get('payload','')[:30]}"
        if k not in seen:
            seen.add(k)
            unique.append(f)
    
    # 4. THE FIX: Save back to Redis with a 24-hour (86400s) TTL
    # This prevents memory leaks if clear() is never called.
    r.set(key, json.dumps(unique), ex=86400)

def get_findings(job_id: str) -> list:
    """Retrieves all findings currently aggregated for a job."""
    if r is None:
        return []
    data = r.get(f"agg:{job_id}")
    return json.loads(data) if data else []

def clear(job_id: str):
    """Manually deletes the aggregation bucket (called after report generation)."""
    if r is None:
        return
    r.delete(f"agg:{job_id}")