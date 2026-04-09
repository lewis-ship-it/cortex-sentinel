# task_queue/redis_client.py

import redis
import json
import os
import time
import logging

# Load environment variables
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

try:
    # If the URL starts with rediss:// (Upstash/Cloud), 
    # we let the URL handle everything. No manual 'ssl' arguments.
    if REDIS_URL.startswith("rediss://"):
        r = redis.Redis.from_url(
            REDIS_URL, 
            decode_responses=True
        )
    else:
        # Standard local connection
        r = redis.Redis.from_url(
            REDIS_URL, 
            decode_responses=True
        )
    
    # Connection Test
    r.ping()
    print("✅ Successfully connected to Redis")
    
except Exception as e:
    logging.error(f"❌ Redis Connection Failed: {e}")
    # Create a dummy object so the rest of the script doesn't crash on import
    r = None 

MAX_RETRIES = 3

def push(queue: str, data: dict) -> None:
    if r:
        data["retries"] = data.get("retries", 0)
        r.lpush(queue, json.dumps(data))

def pop(queue: str):
    if not r:
        return None
    try:
        data = r.rpop(queue)
        if data:
            return json.loads(data)
    except Exception as e:
        logging.error(f"[REDIS] Pop error: {e}")
    return None

def retry(queue: str, job: dict, error: str = None) -> None:
    job["retries"] = job.get("retries", 0) + 1
    if job["retries"] > MAX_RETRIES:
        logging.error(f"[DROP] Job failed permanently: {job}")
        return
    logging.warning(f"[RETRY] {queue} | Attempt {job['retries']} | Error: {error}")
    time.sleep(1)
    push(queue, job)