import redis
import json
import os
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
QUEUE_NAME = "scan_queue"

# We use a very clean initialization. 
# If your URL starts with rediss:// (SSL), the library handles it automatically.
try:
    r = redis.from_url(
        REDIS_URL, 
        decode_responses=True
    )
    # Ping to check connection immediately
    r.ping()
    print("✅ Successfully connected to Redis")
except Exception as e:
    print(f"❌ Redis Connection Error: {e}")

def enqueue_scan(job):
    r.rpush(QUEUE_NAME, json.dumps(job))

def dequeue_scan():
    print(f"[*] Monitoring queue: {QUEUE_NAME}...")
    try:
        # blpop returns (queue_name, data)
        res = r.blpop(QUEUE_NAME, timeout=0) 
        if res:
            return json.loads(res[1])
    except Exception as e:
        print(f"[!] Worker Error during dequeue: {e}")
    return None