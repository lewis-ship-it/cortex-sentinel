import redis
import os
import json
from dotenv import load_dotenv

load_dotenv()

# Use 'rediss://' for Upstash SSL compatibility.
# NEVER hardcode credentials here — always use .env
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

redis_client = redis.from_url(
    REDIS_URL,
    ssl_cert_reqs=None,  # Required for cloud environments (e.g. Upstash)
    decode_responses=True
)


def enqueue_scan(data):
    """Pushes a job into the queue."""
    redis_client.lpush("scan_queue", json.dumps(data))
    print(f"DEBUG: Job sent to Redis: {data.get('job_id')}")


def dequeue_scan():
    """Pops a job from the queue."""
    data = redis_client.rpop("scan_queue")
    if data:
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            print(f"[REDIS] Failed to parse job: {e}")
            return None
    return None