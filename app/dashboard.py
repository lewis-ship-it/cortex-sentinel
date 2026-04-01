import streamlit as st
import requests
import pandas as pd
import time
import os
import plotly.express as px
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# --- CONFIG ---
API_BASE = os.getenv("API_URL", "http://localhost:8000")
API_KEY = os.getenv("SENTINEL_API_KEY", "test-key-123")
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
    scan_mode = st.select_slider("Scan Intensity", options=["Stealth", "Fast", "Deep"], value="Fast")
    
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
        c_val = st.text_input("Value")
        auth_config = {"type": "cookie", "name": c_name, "value": c_val}

    st.divider()
    
    if st.button("🚀 LAUNCH FULL AUDIT"):
        payload = {
            "target": target_url,
            "mode": scan_mode.lower(),
            "auth": auth_config
        }
        try:
            res = requests.post(f"{API_BASE}/scan", json=payload, headers=HEADERS)
            if res.status_code == 200:
                st.session_state.job_id = res.json().get("job_id")
                st.toast("Scan enqueued successfully!", icon="🛡️")
            else:
                st.error(f"Launch Failed: {res.text}")
        except Exception as e:
            st.error(f"Connection Error: {e}")

# --- MAIN INTERFACE ---
if not st.session_state.job_id:
    st.info("👋 Welcome. Enter a target URL in the sidebar to begin an autonomous security audit.")
    # Placeholder Graphics
    c1, c2 = st.columns(2)
    with c1:
        st.image("https://raw.githubusercontent.com/streamlit/fluent-ui-components/master/docs/assets/banner.png")
else:
    # --- LIVE MONITORING SECTION ---
    st.subheader(f"🛰️ Active Job: {st.session_state.job_id}")
    
    progress_bar = st.progress(0)
    status_msg = st.empty()
    
    # Poll API for status
    try:
        status_res = requests.get(f"{API_BASE}/status/{st.session_state.job_id}", headers=HEADERS)
        if status_res.status_code == 200:
            data = status_res.json()
            p_val = data.get("progress", 0)
            progress_bar.progress(p_val)
            status_msg.markdown(f"**Current Task:** {data.get('status', 'Initializing...')}")
            
            if data.get("status") == "done":
                # Fetch final results once
                if not st.session_state.scan_results:
                    res_res = requests.get(f"{API_BASE}/result/{st.session_state.job_id}", headers=HEADERS)
                    st.session_state.scan_results = res_res.json()
        
    except Exception as e:
        st.error(f"Status Polling Error: {e}")

    # --- RESULTS TABS ---
    if st.session_state.scan_results:
        results = st.session_state.scan_results
        findings = results.get("findings", [])
        
        t1, t2, t3 = st.tabs(["📊 Overview", "🧠 AI Reasoning", "⚙️ Raw Data"])
        
        with t1:
            # Metric Row
            m1, m2, m3, m4 = st.columns(4)
            criticals = [f for f in findings if f.get('severity') == 'Critical']
            highs = [f for f in findings if f.get('severity') == 'High']
            
            m1.metric("Critical", len(criticals))
            m2.metric("High", len(highs))
            m3.metric("Verified", len(findings))
            m4.metric("Engine Status", "Complete")

            # Chart
            if findings:
                df = pd.DataFrame(findings)
                fig = px.pie(df, names='severity', title='Risk Distribution', 
                             color_discrete_map={'Critical':'#ff4b4b', 'High':'#ff9f1c', 'Medium':'#ffeb3b'})
                st.plotly_chart(fig, use_container_width=True)

        with t2:
            st.subheader("AI Auditor Analysis")
            for f in findings:
                severity_color = "#ff4b4b" if f.get('severity') == 'Critical' else "#ff9f1c"
                with st.expander(f"{f.get('title')} - {f.get('severity')}"):
                    st.markdown(f"### Impact")
                    st.write(f.get('impact', 'No impact provided.'))
                    
                    st.markdown("### 🧪 Proof of Concept")
                    poc = f.get('poc_details', {})
                    if poc:
                        st.code(poc.get('curl_command', 'N/A'), language="bash")
                        st.caption(f"**Payload:** `{poc.get('payload')}`")
                    
                    st.markdown("### 🛠️ Remediation")
                    st.success(f.get('remediation', 'Follow standard OWASP patching.'))

        with t3:
            st.json(results)