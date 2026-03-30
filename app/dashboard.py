import streamlit as st
import sys
import os
import pandas as pd

# Path fix for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.database import DatabaseManager
from scanner.active_engine import ActiveScanner

db = DatabaseManager()
scanner = ActiveScanner()

st.set_page_config(page_title="Cortex Sentinel Dashboard", layout="wide")
st.title("🛡️ Cortex Sentinel: Security Report")

target_url = st.sidebar.text_input("Enter Target URL", "http://zero.webappsecurity.com")

# 1. LIVE SCAN BUTTON
if st.sidebar.button("🚀 Run Live Scan"):
    with st.status(f"Scanning {target_url}...", expanded=True) as status_box:
        def update_status(msg):
            st.write(msg)
        
        # Trigger the merged scan logic
        findings = scanner.scan_url(target_url, progress_callback=update_status)
        
        status_box.write("💾 Saving results to database...")
        db.save_scan(target_url, {}, {}, vulnerabilities=findings)
        status_box.update(label="Scan Complete!", state="complete", expanded=False)
    st.rerun()

# 2. FETCH HISTORY BUTTON
if st.sidebar.button("Fetch Latest Report"):
    data = db.get_cached_result(target_url)
    if data:
        st.success(f"Analysis for: {data['url']}")
        
        # Severity Grade
        total_score = data.get('severity_score', 0)
        if total_score >= 9: grade, color = "F (CRITICAL)", "normal"
        elif total_score >= 7: grade, color = "D (HIGH RISK)", "normal"
        elif total_score >= 4: grade, color = "C (WARNING)", "off"
        elif total_score > 0: grade, color = "B (FAIR)", "off"
        else: grade, color = "A (SECURE)", "inverse"

        st.metric(label="Safety Grade", value=grade, delta="-Risk Identified" if total_score > 0 else "Safe", delta_color=color)

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("🌐 Security Headers")
            st.json(data.get('headers', {}))
        with col2:
            st.subheader("🔒 SSL/TLS Status")
            ssl = data.get('ssl_info', {})
            st.info(f"Status: {ssl.get('status', 'Unknown')}")

        st.divider()
        st.subheader("🚀 Active Injection Results")
        vulns = data.get('vulnerabilities', [])
        if vulns:
            df = pd.DataFrame(vulns)
            df = df[['type', 'severity', 'score', 'description']]
            st.dataframe(df.style.background_gradient(cmap='Reds', subset=['score']), use_container_width=True)
        else:
            st.success("Target passed all active tests.")
    else:
        st.error("No scan history found.")