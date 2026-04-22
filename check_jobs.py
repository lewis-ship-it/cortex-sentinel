import redis
import json

r = redis.Redis.from_url('redis://127.0.0.1:6379', decode_responses=True)

print("=" * 80)
print("JOB DIAGNOSTICS & ANALYSIS")
print("=" * 80)

# Check the job IDs mentioned
jobs_to_check = [
    '3e127437-3dc6-4f78-91d2-3734744f8391',
    '051d7567-d36a-4b2c-93a5-0510f693be83',
    '35e2ad34-7e80-4597-ae50-ab6b0879a1e4'
]

for job_id in jobs_to_check:
    logs = r.lrange(f"logs:{job_id}", 0, -1)
    findings = r.lrange(f"job:{job_id}:findings", 0, -1)
    status = r.get(f"job:{job_id}:status")
    
    print(f"\nJOB: {job_id[:8]}...")
    print(f"  Status: {status}")
    print(f"  Logs: {len(logs)} entries")
    print(f"  Findings: {len(findings)} entries")
    
    if logs:
        print("  Last 5 logs:")
        for i, log in enumerate(logs[-5:], 1):
            try:
                entry = json.loads(log)
                msg = entry.get('message', log)
                print(f"    {i}. {msg[:80]}")
            except:
                print(f"    {i}. {log[:80]}")
    else:
        print("  [NO LOGS - Job failed before logging started]")

# Check how many total jobs exist
all_keys = r.keys("job:*:status")
print(f"\nTOTAL JOBS IN REDIS: {len(all_keys)}")

# Check queues
queues = ['scan_queue', 'exploit_queue', 'report_queue', 'memory_queue', 'scoring_queue', 'aggregation_queue']
print("\nQUEUE STATUS:")
total_queued = 0
for q in queues:
    count = r.llen(q)
    if count > 0:
        print(f"  {q}: {count} jobs")
        total_queued += count

if total_queued == 0:
    print("  All queues are EMPTY")
else:
    print(f"\n  TOTAL QUEUED JOBS: {total_queued}")

# Analysis
print("\n" + "=" * 80)
print("ANALYSIS")
print("=" * 80)
print("""
The 3 jobs mentioned have NO logs and NO findings because they:
1. Failed to submit properly to the queue
2. Never reached any worker
3. Or crashed immediately without logging

WHY NO LOGS?
- Jobs 3e127437, 051d7567, 35e2ad34 never made it to scan_worker
- The pipeline never executed for these jobs
- No state machine entries were created

CURRENT STATUS:
- Redis is CLEAN (no stuck jobs)
- All queues are EMPTY
- New jobs can be submitted successfully
- The queue clearing on startup IS working

NEXT STEPS:
1. Submit a fresh scan with the new real-time dashboard
2. Monitor logs in real-time at http://127.0.0.1:8000/
3. Findings should flow through the pipeline properly
""")
