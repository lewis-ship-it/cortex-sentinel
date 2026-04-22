#!/usr/bin/env python3
"""
Diagnostic script for Cortex Sentinel.
Checks Redis connectivity, job status, and logs.
"""

import redis
import json
import sys
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

def test_redis():
    """Test Redis connectivity."""
    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        ping = r.ping()
        print("✓ Redis is accessible")
        return r
    except Exception as e:
        print(f"✗ Redis connection failed: {e}")
        sys.exit(1)

def check_job_logs(r, job_id):
    """Check logs for a specific job."""
    key = f"logs:{job_id}"
    if not r.exists(key):
        print(f"  ✗ No logs found for job {job_id}")
        return False
    
    logs = r.lrange(key, 0, -1)
    if not logs:
        print(f"  ✗ Job exists but has no log entries")
        return False
    
    print(f"  ✓ Found {len(logs)} log entries for job {job_id}:")
    for i, log_entry in enumerate(logs[-10:], start=1):  # Show last 10
        try:
            entry = json.loads(log_entry)
            print(f"    [{entry.get('time', '?')}] {entry.get('message', '?')}")
        except:
            print(f"    {log_entry[:80]}")
    
    return True

def list_all_jobs(r):
    """List all jobs in Redis."""
    print("\nListing all jobs with logs:")
    keys = r.keys("logs:*")
    
    if not keys:
        print("  No jobs found in Redis")
        return
    
    for key in sorted(keys):
        job_id = key.replace("logs:", "")
        count = r.llen(key)
        print(f"  {job_id}: {count} log entries")

def main():
    print("═" * 60)
    print("Cortex Sentinel Diagnostic Tool")
    print("═" * 60)
    
    # Test Redis
    r = test_redis()
    
    # Check if job_id was provided as argument
    if len(sys.argv) > 1:
        job_id = sys.argv[1]
        print(f"\nChecking job: {job_id}")
        check_job_logs(r, job_id)
    
    # List all jobs
    list_all_jobs(r)
    
    print("\n" + "═" * 60)
    print("Diagnostic complete")
    print("═" * 60)

if __name__ == "__main__":
    main()
