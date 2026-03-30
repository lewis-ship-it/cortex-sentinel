import redis
import os
from dotenv import load_dotenv

# 1. Load the URL from your .env file
load_dotenv()
REDIS_URL = os.getenv("REDIS_URL")

# 2. Connect to the Cloud
# Using the URL you got: redis://:mQ6OU5...
try:
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    
    # 3. Test the connection
    r.set("sentinel_status", "System Online")
    value = r.get("sentinel_status")
    print(f"✅ Connection Successful! Sentinel is: {value}")
    
except Exception as e:
    print(f"❌ Connection Failed: {e}")