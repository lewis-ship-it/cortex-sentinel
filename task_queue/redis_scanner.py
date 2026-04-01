import redis
import os
from dotenv import load_dotenv

load_dotenv()

# THE FIX: Change "redis://" to "rediss://" (with two 's' for SSL)
# This forces the client to use a secure encrypted connection required by Upstash.
REDIS_URL = os.getenv("REDIS_URL", "rediss://default:AZk4AAIncDE5ODg1MThmZDVhZDY0Y2I1OWI2Yjg1YmQ5M2ZjNTJiMXAxMzkyMjQ@related-gopher-39224.upstash.io:6379")

# Initialize the client with SSL certificate requirements disabled (common for Upstash)
redis_client = redis.from_url(
    REDIS_URL, 
    ssl_cert_reqs=None, 
    decode_responses=True
)

def enqueue_scan(data):
    # This pushes your scan job into the Upstash cloud queue
    redis_client.lpush("scan_queue", str(data))
    print(f"DEBUG: Job sent to Upstash Cloud: {data.get('job_id')}")