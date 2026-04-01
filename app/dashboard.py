import streamlit as st
import requests
import pandas as pd
import time
import os
import json  # Added for safe cookie parsing
import plotly.express as px
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# --- CONFIG ---
# Pulls from Streamlit Cloud Secrets, falls back to localhost for your PC
API_BASE = st.secrets.get("API_URL", "http://localhost:8000")
API_KEY = st.secrets.get("SENTINEL_API_KEY", "test-key-123")
HEADERS = {"x-api-key": API_KEY, "Content-Type": "application/json"}

st.set_page_config(
    page_title="Sentinel AI | Security Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS FOR MODERN DARK THEME ---
st.markdown("""
    <style>
    .stMetric { background-color: #161b22; border: 1px solid #30363d; padding: 15px; border-radius: 10px; }
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #238636; color: white; border: none; }
    .stButton>button:hover { background-color: #2ea043; border: none; }
    .report-card { background-color: #0d1117; border: 1px solid #30363d; padding: 20px; border-radius: 10px; margin-bottom: 10px; }
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE INITIALIZATION ---
if 'job_id' not in st.session_state:
    st.session_state.job_id = None
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None

# --- SIDEBAR: CONFIGURATION ---
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=60)
    st.title("Sentinel AI")
    st.caption("v2.0 | Autonomous Auditor")
    st.divider()
    
    target_url = st.text_input("🎯 Target URL", "http://testphp.vulnweb.com")
    scan_mode = st.select_slider("Scan Intensity", options=["stealth", "fast", "deep"], value="fast")
    
    st.subheader("🔐 Authentication")
    auth_type = st.selectbox("Method", ["None", "Login Form", "Session Cookie"])
    
    auth_config = None
    if auth_type == "Login Form":
        u = st.text_input("Username Field", "user")
        p = st.text_input("Password Field", "pass", type="password")
        l_url = st.text_input("Login URL", f"{target_url}/login")
        auth_config = {"type": "form", "url": l_url, "fields": {"user": u, "pass": p}}
    
    elif auth_type == "Session Cookie":
        c_name = st.text_input("Cookie Name", "PHPSESSID")
        c_val = st.text_input("Value (JSON format)", '{"ID": "12345"}')
        
        # --- THE FIX: SAFE PARSING ---
        if c_val:
            try:
                # Replaced eval() with safe json.loads()
                parsed_val = json.loads(c_val)
                auth_config = {"type": "cookie", "name": c_name, "value": parsed_val}
            except json.JSONDecodeError:
                st.error("❌ Invalid JSON in Cookie Value. Use format: {\"key\": \"value\"}")
                auth_config = None

    st.divider()
    
    if st.button("🚀 LAUNCH FULL AUDIT"):
        payload = {
            "url": target_url,
            "mode": scan_mode,
            "auth": auth_config
        }
        try:
            res = requests.post(f"{API_BASE}/scan", json=payload, headers=HEADERS)
            if res.status_code == 200:
                st.session_state.job_id = res.json().get("job_id")
                st.session_state.scan_results = None # Reset for new scan
                st.toast("Scan enqueued successfully!", icon="🛡️")
            else:
                st.error(f"Launch Failed: {res.text}")
        except Exception as e:
            st.error(f"Connection Error: {e}")

# --- MAIN INTERFACE ---
if not st.session_state.job_id:
    st.info("👋 Welcome. Enter a target URL in the sidebar to begin an autonomous security audit.")
    st.image("https://raw.githubusercontent.com/streamlit/fluent-ui-components/master/docs/assets/banner.png")
else:
    # --- LIVE MONITORING SECTION ---
    st.subheader(f"🛰️ Active Job: {st.session_state.job_id}")
    
    progress_bar = st.progress(0)
    status_msg = st.empty()
    
    # Poll API for status
    try:
        status_res = requests.get(f"{API_BASE}/job/{st.session_state.job_id}", headers=HEADERS)
        if status_res.status_code == 200:
            data = status_res.json()
            # Assuming data returns {"status": "...", "progress": 50}
            p_val = data.get("progress", 0)
            progress_bar.progress(p_val)
            status_msg.markdown(f"**Current Task:** {data.get('status', 'Initializing...')}")
            
            if data.get("status") == "done" or p_val == 100:
                if not st.session_state.scan_results:
                    res_res = requests.get(f"{API_BASE}/result/{st.session_state.job_id}", headers=HEADERS)
                    st.session_state.scan_results = res_res.json()
        
    except Exception as e:
        st.error(f"Status Polling Error: {e}")

    # --- RESULTS TABS ---
    if st.session_state.scan_results:
        results = st.session_state.scan_results
        findings = results.get("vulnerabilities", [])
        
        t1, t2, t3 = st.tabs(["📊 Overview", "🧠 AI Reasoning", "⚙️ Raw Data"])
        
        with t1:
            m1, m2, m3, m4 = st.columns(4)
            criticals = [f for f in findings if f.get('severity') == 'Critical']
            highs = [f for f in findings if f.get('severity') == 'High']
            
            m1.metric("Critical", len(criticals))
            m2.metric("High", len(highs))
            m3.metric("Verified", len(findings))
            m4.metric("Status", "Complete")

            if findings:
                df = pd.DataFrame(findings)
                fig = px.pie(df, names='severity', title='Risk Distribution', 
                             color_discrete_map={'Critical':'#ff4b4b', 'High':'#ff9f1c', 'Medium':'#ffeb3b'})
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.success("No vulnerabilities detected in this scan.")

        with t2:
            st.subheader("AI Auditor Analysis")
            for f in findings:
                with st.expander(f"{f.get('title', 'Unknown Issue')} - {f.get('severity', 'Low')}"):
                    st.markdown("### Impact")
                    st.write(f.get('description', 'No description provided.'))
                    
                    st.markdown("### 🧪 Proof of Concept")
                    st.code(f.get('poc', 'N/A'))
                    
                    st.markdown("### 🛠️ Remediation")
                    st.info(f.get('remediation', 'Apply latest security patches.'))

        with t3:
            st.json(results)