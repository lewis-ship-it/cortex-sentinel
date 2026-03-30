import test_redis
import json
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
QUEUE_NAME = "scan_queue"

r = test_redis.Redis.from_url(REDIS_URL, decode_responses=True)

def enqueue_scan(job):
    r.rpush(QUEUE_NAME, json.dumps(job))

def dequeue_scan():
    _, job = r.blpop(QUEUE_NAME)
    return json.loads(job)