import redis
import os
import json
from dotenv import load_dotenv

load_dotenv()

# Use 'rediss://' for Upstash SSL compatibility
REDIS_URL = os.getenv("REDIS_URL", "rediss://default:AZk4AAIncDE5ODg1MThmZDVhZDY0Y2I1OWI2Yjg1YmQ5M2ZjNTJiMXAxMzkyMjQ@related-gopher-39224.upstash.io:6379")

redis_client = redis.from_url(
    REDIS_URL, 
    ssl_cert_reqs=None, # Required for cloud environments to connect to Upstash
    decode_responses=True
)

def enqueue_scan(data):
    """Pushes a job into the queue."""
    # Convert dict to string for Redis storage
    redis_client.lpush("scan_queue", json.dumps(data))
    print(f"DEBUG: Job sent to Upstash: {data.get('job_id')}")

def dequeue_scan():
    """Pops a job from the queue. This was the missing function."""
    data = redis_client.rpop("scan_queue")
    if data:
        return json.loads(data)
    return None