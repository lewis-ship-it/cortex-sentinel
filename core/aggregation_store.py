import redis
import os
import json

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def add_findings(job_id, findings):
    key = f"agg:{job_id}"
    existing = r.get(key)
    data = json.loads(existing) if existing else []
    data.extend(findings)

    # Deduplicate by (type, url, payload)
    unique = {}
    for f in data:
        k = f"{f.get('type')}_{f.get('url')}_{f.get('payload', '')}"
        unique[k] = f

    r.set(key, json.dumps(list(unique.values())))


def get_findings(job_id):
    key = f"agg:{job_id}"
    data = r.get(key)
    return json.loads(data) if data else []


def clear(job_id):
    r.delete(f"agg:{job_id}")
