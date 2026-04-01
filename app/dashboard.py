import streamlit as st
import requests
import pandas as pd
import time
import os
import json
import plotly.express as px
from streamlit_lottie import st_lottie
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# --- 1. CONFIG & ASSETS ---
API_BASE = st.secrets.get("API_URL", "https://sentinel-api-0qde.onrender.com")
API_KEY = st.secrets.get("SENTINEL_API_KEY", "test-key-123")
HEADERS = {"x-api-key": API_KEY, "Content-Type": "application/json"}

st.set_page_config(page_title="Sentinel AI | Security Command Center", page_icon="🛡️", layout="wide")

def load_lottie(url):
    r = requests.get(url)
    return r.json() if r.status_code == 200 else None

radar_anim = load_lottie("https://lottie.host/80783363-f938-4e58-958b-0803c400490b/O6fX8FhG1m.json")

# --- 2. CUSTOM CSS ---
st.markdown("""
    <style>
    .stMetric { background-color: #161b22; border: 1px solid #30363d; padding: 15px; border-radius: 10px; }
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #238636; color: white; border: none; }
    .report-card { background-color: #0d1117; border: 1px solid #30363d; padding: 20px; border-radius: 10px; margin-bottom: 10px; }
    </style>
    """, unsafe_allow_html=True)

# --- 3. SIDEBAR: SCAN CONFIGURATION ---
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
        c_val = st.text_input("Value (JSON)", '{"ID": "12345"}')
        if c_val:
            try: auth_config = {"type": "cookie", "name": c_name, "value": json.loads(c_val)}
            except: st.error("❌ Invalid JSON")

    st.divider()
    if st.button("🚀 LAUNCH FULL AUDIT"):
        payload = {"url": target_url, "mode": scan_mode, "auth": auth_config}
        res = requests.post(f"{API_BASE}/scan", json=payload, headers=HEADERS)
        if res.status_code == 200:
            st.session_state.job_id = res.json().get("job_id")
            st.session_state.scan_results = None
            st.toast("Scan enqueued!", icon="🛡️")

# --- 4. MAIN INTERFACE & LIVE PROGRESS ---
if not st.session_state.get("job_id"):
    st.info("👋 Welcome. Enter a target URL in the sidebar to begin.")
else:
    status_container = st.empty()
    
    # --- POLLING LOOP ---
    while True:
        try:
            # Get latest status from your Render API
            resp = requests.get(f"{API_BASE}/job/{st.session_state.job_id}", headers=HEADERS).json()
            status = resp.get("status", "queued")
            progress = resp.get("progress", 0)

            with status_container.container():
                if status == "done":
                    st.success("✅ Audit Complete!")
                    st.balloons()
                    # Fetch and store final findings
                    final_res = requests.get(f"{API_BASE}/result/{st.session_state.job_id}", headers=HEADERS).json()
                    st.session_state.scan_results = final_res.get("vulnerabilities", [])
                    break 
                
                elif "failed" in status.lower():
                    st.error(f"❌ Scan Error: {status}")
                    break

                else:
                    # PROGRESS UI
                    c1, c2 = st.columns([1, 2])
                    with c1:
                        st_lottie(radar_anim, height=250, key="scanning")
                    with c2:
                        st.header(f"🛡️ Scan in Progress...")
                        st.subheader(f"Current Phase: {status}")
                        st.progress(progress / 100)
                        st.write("Sentinel AI is analyzing attack vectors and testing payloads.")
            
            time.sleep(2) # Refresh UI every 2 seconds
        except Exception as e:
            st.warning("Reconnecting to Sentinel API...")
            time.sleep(5)

# --- 5. RESULTS DASHBOARD (ORIGINAL DESIGN) ---
if st.session_state.get("scan_results"):
    findings = st.session_state.scan_results
    
    t1, t2 = st.tabs(["📊 Executive Summary", "🔍 Technical Findings"])
    
    with t1:
        m1, m2, m3, m4 = st.columns(4)
        crit = [f for f in findings if f.get('severity') == 'Critical']
        high = [f for f in findings if f.get('severity') == 'High']
        
        m1.metric("Critical", len(crit))
        m2.metric("High", len(high))
        m3.metric("Verified", len(findings))
        m4.metric("Status", "Complete")

        if findings:
            df = pd.DataFrame(findings)
            fig = px.pie(df, names='severity', title='Risk Distribution', 
                         color_discrete_map={'Critical':'#ff4b4b', 'High':'#ff9f1c'})
            st.plotly_chart(fig, use_container_width=True)

    with t2:
        for f in findings:
            with st.expander(f"{f.get('title', 'Issue')} - {f.get('severity', 'Medium')}"):
                st.markdown(f"**Description**: {f.get('description')}")
                st.code(f.get('poc', 'N/A'), language="http")