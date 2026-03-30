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

# 1. LIVE SCAN LOGIC
if st.sidebar.button("🚀 Run Live Scan"):
    with st.status(f"Scanning {target_url}...", expanded=True) as status_box:
        def update_status(msg):
            st.write(msg)
        
        findings = scanner.scan_url(target_url, progress_callback=update_status)
        
        status_box.write("💾 Attempting to save to Supabase...")
        try:
            # We send empty dicts for headers/ssl to avoid schema conflicts for now
            db.save_scan(target_url, {}, {}, vulnerabilities=findings)
            status_box.update(label="Scan Complete & Saved!", state="complete", expanded=False)
        except Exception as e:
            st.error(f"Database Save Failed: {e}")
            status_box.update(label="Scan Finished (Save Error)", state="error")
    st.rerun()

# 2. FETCH HISTORY LOGIC
if st.sidebar.button("Fetch Latest Report"):
    data = db.get_cached_result(target_url)
    if data:
        st.success(f"Analysis for: {data['url']}")
        
        score = data.get('severity_score', 0)
        # Grade Logic
        if score >= 9: grade, color = "F (CRITICAL)", "normal"
        elif score >= 7: grade, color = "D (HIGH)", "normal"
        elif score > 0: grade, color = "B (FAIR)", "off"
        else: grade, color = "A (SECURE)", "inverse"

        st.metric(label="Safety Grade", value=grade, delta_color=color)

        st.divider()
        st.subheader("🚀 Vulnerability Table")
        vulns = data.get('vulnerabilities', [])
        if vulns:
            df = pd.DataFrame(vulns)
            st.dataframe(df, use_container_width=True)
        else:
            st.success("No vulnerabilities found.")
    else:
        st.error("No record found for this URL.")