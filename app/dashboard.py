import streamlit as st
import requests
import pandas as pd
import time

# CONFIG
API_BASE = "http://localhost:8000"
API_KEY = "test-key-123"  # change this in production

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

st.set_page_config(page_title="Cortex Sentinel", layout="wide")

st.title("🛡️ Cortex Sentinel")
st.caption("Production Security Scanner Dashboard")

# SIDEBAR
st.sidebar.header("Scan Configuration")

target_url = st.sidebar.text_input(
    "Target URL",
    "http://testphp.vulnweb.com"
)

scan_mode = st.sidebar.selectbox(
    "Scan Mode",
    ["fast", "deep"]
)

start_scan = st.sidebar.button("🚀 Start Scan")
load_report = st.sidebar.button("📂 Load Last Report")

# -----------------------------
# START SCAN
# -----------------------------
if start_scan:
    with st.spinner("Submitting scan job..."):
        try:
            res = requests.post(
                f"{API_BASE}/scan",
                json={"url": target_url, "mode": scan_mode},
                headers=HEADERS,
                timeout=10
            )

            data = res.json()
            job_id = data.get("job_id")

            if not job_id:
                st.error("Failed to create job")
                st.stop()

            st.success(f"Job queued: {job_id}")

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
        log_box.text("\n".join(logs[-10:]))

    # POLL LOOP
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

            progress_bar.progress(progress)
            status_text.info(f"Status: {status} ({progress}%)")

            log(f"{time.strftime('%H:%M:%S')} → {status}")

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
            f"{API_BASE}/result/{target_url}",
            headers=HEADERS
        )

        result_data = result_res.json()

        vulns = result_data.get("vulnerabilities", [])

        st.divider()
        st.subheader("📊 Scan Results")

        if vulns:
            df = pd.DataFrame(vulns)

            # Metrics
            col1, col2, col3 = st.columns(3)

            col1.metric("Critical", len(df[df["severity"] == "Critical"]))
            col2.metric("High", len(df[df["severity"] == "High"]))
            col3.metric("Medium", len(df[df["severity"] == "Medium"]))

            st.divider()

            st.subheader("🔎 Detailed Findings")
            st.dataframe(df, use_container_width=True)

        else:
            st.success("No vulnerabilities found")

    except Exception as e:
        st.error(f"Failed to fetch results: {e}")


# -----------------------------
# LOAD PREVIOUS REPORT
# -----------------------------
if load_report:
    with st.spinner("Loading report..."):
        try:
            res = requests.get(
                f"{API_BASE}/result/{target_url}",
                headers=HEADERS
            )

            data = res.json()

            if "status" in data and data["status"] == "not_found":
                st.error("No previous scan found")
                st.stop()

            st.success(f"Loaded report for {target_url}")

            score = data.get("severity_score", 0)

            # GRADE SYSTEM
            if score >= 9:
                grade = "F (Critical)"
            elif score >= 7:
                grade = "D (High Risk)"
            elif score >= 4:
                grade = "C (Moderate)"
            elif score > 0:
                grade = "B (Low Risk)"
            else:
                grade = "A (Secure)"

            st.metric("Security Grade", grade)

            st.divider()

            vulns = data.get("vulnerabilities", [])

            if vulns:
                df = pd.DataFrame(vulns)
                st.dataframe(df, use_container_width=True)
            else:
                st.success("No vulnerabilities recorded")

        except Exception as e:
            st.error(f"Error loading report: {e}")