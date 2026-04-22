"""
Redis initialization - clear queues on startup to ensure clean state.
"""

import redis
import os
from task_queue.queues import (
    CRAWL_QUEUE, SCAN_QUEUE, BROWSER_QUEUE, SAST_QUEUE,
    EXPLOIT_QUEUE, AGGREGATION_QUEUE, REPORT_QUEUE,
    NETWORK_QUEUE, MOBILE_QUEUE, API_QUEUE,
    PLANNER_QUEUE, MEMORY_QUEUE, SCORING_QUEUE, AUTH_QUEUE
)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

def clear_redis_queues():
    """
    Clear all job queues on initialization.
    Ensures previous jobs don't re-trigger.
    """
    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        
        queues = [
            CRAWL_QUEUE, SCAN_QUEUE, BROWSER_QUEUE, SAST_QUEUE,
            EXPLOIT_QUEUE, AGGREGATION_QUEUE, REPORT_QUEUE,
            NETWORK_QUEUE, MOBILE_QUEUE, API_QUEUE,
            PLANNER_QUEUE, MEMORY_QUEUE, SCORING_QUEUE, AUTH_QUEUE
        ]
        
        for queue in queues:
            count = r.llen(queue)
            if count > 0:
                r.delete(queue)
                print(f"✓ Cleared {queue}: {count} pending jobs")
        
        print("✓ Redis queues cleared successfully")
        
        # Also clear active session state but keep reports/findings
        keys_to_clear = r.keys("job:*:status")
        if keys_to_clear:
            r.delete(*keys_to_clear)
            print(f"✓ Cleared {len(keys_to_clear)} job status keys")
            
    except Exception as e:
        print(f"⚠ Warning: Could not clear Redis queues: {e}")


if __name__ == "__main__":
    clear_redis_queues()