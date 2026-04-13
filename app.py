import streamlit as st
import json
import uuid
import time
import psutil
import subprocess
from datetime import datetime

# Import existing system logic
from task_queue.redis_client import r as redis_conn, push
from task_queue.queues import CRAWL_QUEUE
from storage.database import DatabaseManager

# Initialize Database and Redis
db = DatabaseManager()
r = redis_conn 

st.set_page_config(page_title="Cortex Web-Sentinel", layout="wide")

# --- Helper Functions (Merged from app.py & dashboard.py) ---
def get_worker_status(worker_path):
    """Check if a specific worker process is active."""
    for proc in psutil.process_iter(['cmdline']):
        try:
            if proc.info['cmdline'] and any(worker_path in arg for arg in proc.info['cmdline']):
                return proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

# --- UI Header ---
st.title("🛡️ Cortex Web-Sentinel")

if r is None:
    st.error("❌ Redis Connection Failed. Ensure redis-server is running.")
    st.stop()

tabs = st.tabs(["🚀 Launch", "📊 Monitor", "📄 Reports", "⚙️ System"])

# --- TAB 1: Launch Scan (Functional Entry Point) ---
with tabs[0]:
    st.header("Start Web Audit")
    with st.container(border=True):
        url = st.text_input("Target URL", placeholder="https://testphp.vulnweb.com")
        scan_mode = st.radio("Scan Mode", ["Discovery (Crawl Only)", "Full Audit (Crawl + Scan + Exploit)"], horizontal=True)

    if st.button("🚀 Initialize Global Pipeline", use_container_width=True):
        if url:
            job_id = str(uuid.uuid4())
            payload = {
                "job_id": job_id,
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "mode": scan_mode
            }
            # Kicks off the first worker in the chain
            push(CRAWL_QUEUE, payload)
            st.session_state["active_job"] = job_id
            st.success(f"Job Sent to Redis: {job_id}")
        else:
            st.warning("Please enter a target URL.")

# --- TAB 2: Live Monitor (Merged from dashboard.py) ---
with tabs[1]:
    active_id = st.text_input("Track Job ID", value=st.session_state.get("active_job", ""))
    
    if active_id:
        # Progress Tracking Logic from dashboard.py
        current_stage = r.get(f"status:{active_id}") or "queued"
        stages = ["crawl", "scan", "exploit", "aggregation", "report"]
        
        progress = (stages.index(current_stage) + 1) / len(stages) if current_stage in stages else 0
        st.subheader(f"Status: {current_stage.upper()}")
        st.progress(progress)

        # Live Log Streaming Logic from dashboard.py
        st.divider()
        st.subheader("Real-Time Activity")
        raw_logs = r.lrange(f"log:{active_id}", 0, -1)
        if raw_logs:
            for log in raw_logs[-20:]: # Show last 20 logs as requested in original
                try:
                    entry = json.loads(log)
                    st.caption(f"[{entry.get('time', 'N/A')}] {entry.get('message', '')}")
                except:
                    st.text(log)
        else:
            st.info("Waiting for workers to report activity...")

# --- TAB 3: Reports (Merged from app.py & dashboard.py) ---
with tabs[2]:
    st.header("Vulnerability Reports")
    if active_id:
        report_data = r.get(f"report:{active_id}")
        if report_data:
            report = json.loads(report_data)
            st.success("✅ Final Audit Complete")
            
            # JSON Download Functionality from dashboard.py
            st.json(report)
            st.download_button(
                label="📥 Download JSON Report",
                data=json.dumps(report, indent=4),
                file_name=f"sentinel_report_{active_id}.json",
                mime="application/json"
            )
        else:
            st.write("No final report generated yet for this Job ID.")
    else:
        st.write("Enter a Job ID in the Monitor tab to see report data.")

# --- TAB 4: System (Worker Management from app.py) ---
with tabs[3]:
    st.subheader("Worker Process Controller")
    workers = {
        "Crawl Worker": "workers/crawl_worker.py",
        "Scan Worker": "workers/scan_worker.py",
        "Exploit Worker": "workers/exploit_worker.py"
    }

    for name, path in workers.items():
        pid = get_worker_status(path)
        c1, c2 = st.columns([3, 1])
        with c1:
            st.write(f"**{name}**")
            st.code(f"PID: {pid}" if pid else "Status: OFFLINE")
        with c2:
            if not pid:
                if st.button("Start", key=f"start_{name}"):
                    subprocess.Popen(["python", path])
                    time.sleep(1)
                    st.rerun()
            else:
                if st.button("Stop", key=f"stop_{name}"):
                    psutil.Process(pid).terminate()
                    st.rerun()

# --- Sync & Refresh ---
if st.session_state.get("active_job"):
    time.sleep(4)
    st.rerun()