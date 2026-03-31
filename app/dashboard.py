import streamlit as st
import requests
import pandas as pd
import time
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# CONFIG
API_BASE = "http://localhost:8000"
API_KEY = os.getenv("SENTINEL_API_KEY", "test-key-123")

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

st.set_page_config(
    page_title="Cortex Sentinel | Production Security",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cortex Sentinel")
st.caption("Authenticated Vulnerability Scanner")

# -----------------------------
# SIDEBAR
# -----------------------------
with st.sidebar:
    st.header("Scan Configuration")

    target_url = st.text_input("Target URL", "http://testphp.vulnweb.com")
    scan_mode = st.selectbox("Scan Mode", ["fast", "deep", "stealth"])

    st.divider()

    # 🔐 AUTH CONFIG UI
    st.subheader("🔐 Authentication")

    auth_type = st.selectbox("Auth Type", ["None", "Login", "Cookie"])

    auth_config = None

    if auth_type == "Login":
        login_url = st.text_input("Login URL", "http://testphp.vulnweb.com/login.php")
        username = st.text_input("Username", "test")
        password = st.text_input("Password", "test", type="password")

        auth_config = {
            "type": "login",
            "login_url": login_url,
            "username": username,
            "password": password
        }

    elif auth_type == "Cookie":
        cookie_input = st.text_area("Cookies (JSON)", '{"PHPSESSID":"abc123"}')

        try:
            cookies = eval(cookie_input)
            auth_config = {
                "type": "cookie",
                "cookies": cookies
            }
        except:
            st.warning("Invalid cookie format")

    st.divider()

    start_scan = st.button("🚀 Start Scan")
    load_report = st.button("📂 Last Report")

# -----------------------------
# START SCAN
# -----------------------------
if start_scan:

    payload = {
        "url": target_url,
        "mode": scan_mode,
        "auth": auth_config  # 🔥 SEND TO BACKEND
    }

    with st.spinner("Submitting scan job..."):
        try:
            res = requests.post(
                f"{API_BASE}/scan",
                json=payload,
                headers=HEADERS,
                timeout=10
            )

            data = res.json()
            job_id = data.get("job_id")

            if not job_id:
                st.error("Failed to create job")
                st.stop()

            st.success(f"Job started: {job_id}")

        except Exception as e:
            st.error(f"API Error: {e}")
            st.stop()

    # -----------------------------
    # TRACK JOB
    # -----------------------------
    progress_bar = st.progress(0)
    status_text = st.empty()
    log_box = st.empty()

    logs = []

    def log(msg):
        logs.append(msg)
        log_box.code("\n".join(logs[-10:]))

    while True:
        try:
            job_res = requests.get(
                f"{API_BASE}/job/{job_id}",
                headers=HEADERS,
                timeout=5
            )

            job_data = job_res.json()

            status = job_data.get("status", "unknown")
            progress = job_data.get("progress", 0)

            progress_bar.progress(progress / 100)
            status_text.info(f"{status} ({progress}%)")

            log(f"{datetime.now().strftime('%H:%M:%S')} → {status}")

            if status == "done":
                st.success("Scan complete")
                break

            if status == "failed":
                st.error("Scan failed")
                break

            time.sleep(2)

        except Exception as e:
            st.error(f"Tracking error: {e}")
            break

    # -----------------------------
    # FETCH RESULTS
    # -----------------------------
    try:
        result_res = requests.get(
            f"{API_BASE}/result/{job_id}",
            headers=HEADERS
        )

        result_data = result_res.json()
        vulns = result_data.get("vulnerabilities", [])

        st.subheader("📊 Results")

        if vulns:
            df = pd.DataFrame(vulns)

            col1, col2, col3 = st.columns(3)
            col1.metric("Critical", len(df[df["severity"] == "Critical"]))
            col2.metric("High", len(df[df["severity"] == "High"]))
            col3.metric("Medium", len(df[df["severity"] == "Medium"]))

            st.dataframe(df, use_container_width=True)

        else:
            st.success("No vulnerabilities found")

    except Exception as e:
        st.error(f"Result error: {e}")

# -----------------------------
# LOAD REPORT
# -----------------------------
if load_report:
    st.info("Feature coming: scan history by user")