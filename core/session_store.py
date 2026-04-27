
# core/session_store.py

import redis
import os
import json

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def save_session(job_id, session_data):
    r.set(f"session:{job_id}", json.dumps(session_data))


def get_session(job_id):
    data = r.get(f"session:{job_id}")
    return json.loads(data) if data else None


def delete_session(job_id):
    r.delete(f"session:{job_id}")

