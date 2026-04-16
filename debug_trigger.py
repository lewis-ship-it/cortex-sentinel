import uuid
from task_queue.redis_client import r, push
from task_queue.queues import CRAWL_QUEUE
from storage.database import DatabaseManager

db = DatabaseManager()
job_id = str(uuid.uuid4())
target = "https://google.com" # Or your test target

print(f"--- Manual Trigger for Job {job_id} ---")
db.insert_job(job_id, target)
print("1. Job inserted into Supabase.")

push(CRAWL_QUEUE, {"job_id": job_id, "url": target})
print("2. Job pushed to Redis.")

# Manually push a log to see if the dashboard picks it up
r.lpush(f"logs:{job_id}", "DEBUG: Manual trigger initiated.")
print("3. Debug log pushed to Redis.")
print("--- Check your Streamlit Dashboard now! ---")