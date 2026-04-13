import streamlit as st
import json
import uuid
import time
import redis

# Import your existing client logic
from task_queue.redis_client import r as redis_conn, push
from task_queue.queues import SCAN_QUEUE

# Use the connection already created in redis_client.py to avoid conflicts
r = redis_conn 

st.set_page_config(page_title="Cortex Sentinel", layout="wide")
st.title("🛡️ Cortex Sentinel")

# Check if Redis is actually connected
if r is None:
    st.error("❌ Could not connect to Redis. Check if redis-server is running.")
    st.stop()

# -----------------------
# START SCAN
# -----------------------
st.header("Start Scan")
url = st.text_input("Target URL", placeholder="http://example.com")

if st.button("🚀 Launch Scan"):
    if url:
        job_id = str(uuid.uuid4())
        push(SCAN_QUEUE, {
            "job_id": job_id,
            "url": url,
            "retries": 0
        })
        st.session_state["job_id"] = job_id
        st.success(f"Started: {job_id}")
    else:
        st.warning("Please enter a URL first.")

# -----------------------
# JOB INPUT & TRACKING
# -----------------------
current_job = st.text_input("Active Job ID", value=st.session_state.get("job_id", ""))

if current_job:
    st.subheader(f"Status for {current_job}")
    
    # 1. Progress Bar
    stages = ["scan", "exploit", "aggregation", "report"]
    current_stage = r.get(f"status:{current_job}")
    
    progress = 0
    if current_stage in stages:
        progress = (stages.index(current_stage) + 1) / len(stages)
    
    st.progress(progress)
    st.write(f"**Current Stage:** {current_stage if current_stage else 'Queued...'}")

    # 2. Logs
    st.subheader("Live Logs")
    logs = r.lrange(f"log:{current_job}", 0, -1)
    if logs:
        for log in logs[-10:]: # Show last 10 logs
            try:
                entry = json.loads(log)
                st.caption(f"[{entry['time']}] {entry['message']}")
            except:
                st.text(log)
    else:
        st.info("Waiting for logs...")

    # 3. Report
    st.subheader("Final Report")
    report_data = r.get(f"report:{current_job}")
    if report_data:
        report = json.loads(report_data)
        st.success("✅ Analysis Complete")
        st.json(report)
        st.download_button("Download JSON", data=json.dumps(report), file_name=f"report_{current_job}.json")
    else:
        st.info("Report will appear here once the 'report' stage finishes.")

# -----------------------
# AUTO REFRESH (Only if a job is active)
# -----------------------
if current_job and not r.get(f"report:{current_job}"):
    time.sleep(2)
    st.rerun()