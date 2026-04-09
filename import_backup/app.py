import streamlit as st
import subprocess
import psutil
import os
import time
from core.database import DatabaseManager
from dotenv import load_dotenv

load_dotenv()
db = DatabaseManager()

st.set_page_config(page_title="Sentinel AI Dashboard", layout="wide")

# --- Helper Functions for Process Management ---
def get_worker_status():
    """Check if worker.py is currently running."""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['cmdline'] and "workers/worker.py" in " ".join(proc.info['cmdline']):
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def start_worker():
    """Start the worker as a background process."""
    log_file = open("worker_log.txt", "a")
    # 'python' might need to be 'python3' depending on your OS
    subprocess.Popen(
        ["python", "workers/worker.py"],
        stdout=log_file,
        stderr=log_file,
        start_new_session=True # This 'detaches' it from the UI process
    )

# --- UI Layout ---
st.title("🛡️ Sentinel AI Control Center")

tabs = st.tabs(["🚀 Launch Scan", "📊 Security Reports", "⚙️ System Monitor"])

# --- TAB 1: Launch ---
with tabs[0]:
    st.subheader("New Audit")
    col1, col2 = st.columns(2)
    with col1:
        url = st.text_input("Target URL", placeholder="https://example.com")
    with col2:
        uploaded_file = st.file_uploader("Or Upload Source (ZIP)", type="zip")
    
    if st.button("Start Global Scan", use_container_width=True):
        st.info("Job sent to Redis. Worker will pick it up shortly.")

# --- TAB 2: Reports ---
with tabs[1]:
    st.subheader("Verified Vulnerabilities")
    # In production, you'd fetch real jobs from Supabase here
    # jobs = db.get_jobs()
    st.write("No active reports found. Run a scan to generate AI insights.")

# --- TAB 3: System Monitor (The 'No-Terminal' Fix) ---
with tabs[2]:
    st.subheader("Process Management")
    
    worker_pid = get_worker_status()
    
    if worker_pid:
        st.success(f"✅ Worker is ONLINE (PID: {worker_pid})")
        if st.button("🛑 Stop Worker"):
            psutil.Process(worker_pid).terminate()
            st.rerun()
    else:
        st.error("❌ Worker is OFFLINE")
        if st.button("▶️ Start Worker"):
            start_worker()
            st.toast("Worker starting in background...")
            time.sleep(2)
            st.rerun()

    st.divider()
    st.subheader("System Logs")
    if os.path.exists("worker_log.txt"):
        with open("worker_log.txt", "r") as f:
            logs = f.readlines()
            st.text_area("Last 20 lines of Worker output:", "".join(logs[-20:]), height=200)