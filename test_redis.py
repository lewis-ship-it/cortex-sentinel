import redis
import os
from dotenv import load_dotenv

load_dotenv()

try:
    r = redis.Redis.from_url(os.getenv("REDIS_URL"))
    r.ping()
    print("✅ Connection Successful! Local Redis is talking to Python.")
except Exception as e:
    print(f"❌ Connection Failed: {e}")