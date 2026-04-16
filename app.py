import streamlit as st
import requests
import redis
import json
import os
import time
from datetime import datetime

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
REDIS_URL = "redis://redis:6379"
API_URL = "http://api:8000"
API_KEY = os.getenv("SENTINEL_API_KEY", "test-key-123")

r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

st.set_page_config(layout="wide", page_title="Sentinel Scanner")
st.title("🔥 Sentinel Scanner")

# Auto-refresh every 2 seconds if job is running
job_id = st.session_state.get("job_id")
if job_id:
    logs = r.lrange(f"logs:{job_id}", 0, -1)
    completed = any("Complete" in str(log) for log in logs)
    if not completed:
        time.sleep(2)
        st.rerun()

# ─────────────────────────────────────────────
# START SCAN
# ─────────────────────────────────────────────
st.header("🚀 Start Scan")

col1, col2 = st.columns([3, 1])
with col1:
    target = st.text_input("Target URL", "http://httpbin.org/get?q=test")
with col2:
    start_scan = st.button("▶ Scan", use_container_width=True)

if start_scan:
    with st.spinner("Starting scan..."):
        try:
            res = requests.post(
                f"{API_URL}/scan",
                json={"url": target},
                headers={"x-api-key": API_KEY},
                timeout=5
            )
            if res.status_code == 200:
                job_id = res.json()["job_id"]
                st.session_state["job_id"] = job_id
                st.success(f"✅ Scan started: `{job_id}`")
            else:
                st.error(f"❌ API Error: {res.json().get('detail', res.text)}")
        except Exception as e:
            st.error(f"❌ Failed: {str(e)}")

# ─────────────────────────────────────────────
# JOB STATUS & DATA
# ─────────────────────────────────────────────
job_id = st.session_state.get("job_id")

if job_id:
    st.markdown("---")
    st.header("📊 Scan Status")
    
    # Get all Redis data for this job
    logs = r.lrange(f"logs:{job_id}", 0, -1)
    findings_raw = r.lrange(f"job:{job_id}:findings", 0, -1)
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Job ID", job_id[:8] + "...")
    
    with col2:
        st.metric("Logs", len(logs))
    
    with col3:
        st.metric("Findings Stored", len(findings_raw))
    
    with col4:
        completed = any("Complete" in str(log) for log in logs)
        status = "✅ Done" if completed else "🔄 Running"
        st.metric("Status", status)
    
    # ─────────────────────────────────────────────
    # PARSE FINDINGS
    # ─────────────────────────────────────────────
    st.markdown("---")
    st.header("🎯 Findings")
    
    all_findings = []
    
    # Method 1: Parse from findings Redis key
    for finding_entry in findings_raw:
        try:
            parsed = json.loads(finding_entry)
            if isinstance(parsed, list):
                all_findings.extend(parsed)
            else:
                all_findings.append(parsed)
        except:
            pass
    
    # Method 2: Parse from logs (fallback)
    if not all_findings:
        findings_from_logs = {
            "XSS": [],
            "SQL Injection": [],
            "Reflection": []
        }
        
        for log_entry in logs:
            try:
                parsed = json.loads(log_entry)
                msg = parsed.get("message", "")
                
                if "[XSS]" in msg:
                    param = msg.split("Found in ")[-1] if "Found in" in msg else "unknown"
                    findings_from_logs["XSS"].append({"param": param, "log": msg})
                elif "[SQLi]" in msg:
                    param = msg.split("Found in ")[-1] if "Found in" in msg else "unknown"
                    findings_from_logs["SQL Injection"].append({"param": param, "log": msg})
                elif "[Reflection]" in msg:
                    param = msg.split("Found in ")[-1] if "Found in" in msg else "unknown"
                    findings_from_logs["Reflection"].append({"param": param, "log": msg})
            except:
                pass
        
        # Convert to list format
        for vuln_type, items in findings_from_logs.items():
            for item in items:
                all_findings.append({
                    "type": vuln_type,
                    "param": item.get("param", "unknown"),
                    "source": "log_parse"
                })
    
    # ─────────────────────────────────────────────
    # DISPLAY FINDINGS
    # ─────────────────────────────────────────────
    if all_findings:
        st.success(f"✅ Found {len(all_findings)} vulnerability(ies)")
        
        # Group by type
        findings_by_type = {}
        for finding in all_findings:
            vuln_type = finding.get("type", "Unknown")
            if vuln_type not in findings_by_type:
                findings_by_type[vuln_type] = []
            findings_by_type[vuln_type].append(finding)
        
        # Display grouped
        for vuln_type, items in findings_by_type.items():
            with st.expander(f"{vuln_type} ({len(items)} found)"):
                for i, finding in enumerate(items, 1):
                    st.write(f"**{i}. {vuln_type}**")
                    
                    if "target_url" in finding:
                        st.code(finding["target_url"], language="text")
                    
                    if "param" in finding:
                        st.write(f"Parameter: `{finding['param']}`")
                    
                    if "payload" in finding:
                        st.write(f"Payload: `{finding['payload']}`")
                    
                    if "severity" in finding:
                        st.write(f"Severity: **{finding['severity']}**")
                    
                    st.divider()
    else:
        st.info("No findings detected yet or still scanning...")
    
    # ─────────────────────────────────────────────
    # FULL LOG DUMP
    # ─────────────────────────────────────────────
    st.markdown("---")
    with st.expander("📡 Full Logs (Raw Data)"):
        if logs:
            log_display = []
            for i, log_entry in enumerate(logs):
                try:
                    parsed = json.loads(log_entry)
                    time_str = parsed.get("time", "?")
                    msg = parsed.get("message", "?")
                    log_display.append(f"{i+1:3d}. [{time_str}] {msg}")
                except:
                    log_display.append(f"{i+1:3d}. {log_entry}")
            
            log_text = "\n".join(log_display)
            st.code(log_text, language="log")
        else:
            st.write("No logs")
    
    # ─────────────────────────────────────────────
    # RAW REDIS DEBUG
    # ─────────────────────────────────────────────
    with st.expander("🔧 Redis Debug"):
        st.write(f"**Job ID:** `{job_id}`")
        st.write(f"**Logs key:** `logs:{job_id}` → {len(logs)} entries")
        st.write(f"**Findings key:** `job:{job_id}:findings` → {len(findings_raw)} entries")
        
        if findings_raw:
            st.write("**Raw findings data:**")
            for i, entry in enumerate(findings_raw):
                st.code(entry[:200] + "..." if len(entry) > 200 else entry)

else:
    st.info("👆 Start a scan above")
