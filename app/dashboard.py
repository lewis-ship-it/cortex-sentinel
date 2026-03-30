import streamlit as st
import sys
import os
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.database import DatabaseManager

db = DatabaseManager()
st.set_page_config(page_title="Cortex Sentinel Dashboard", layout="wide")

st.title("🛡️ Cortex Sentinel: Security Report")

target_url = st.sidebar.text_input("Enter Target URL", "https://example.com")

if st.sidebar.button("Fetch Latest Report"):
    data = db.get_cached_result(target_url)

    if data:
        st.success(f"Analysis for: {data['url']}")

        # 1. SECURITY GRADE METRIC
        # Sum the scores to get a total risk profile
        total_score = data.get('severity_score', 0)

        # Grade Logic
        if total_score >= 9:
            grade, color = "F (CRITICAL)", "normal"
        elif total_score >= 7:
            grade, color = "D (HIGH RISK)", "normal"
        elif total_score >= 4:
            grade, color = "C (WARNING)", "off"
        elif total_score > 0:
            grade, color = "B (FAIR)", "off"
        else:
            grade, color = "A (SECURE)", "inverse"

        st.metric(
            label="Cortex Sentinel Safety Grade",
            value=grade,
            delta="-Risk Identified" if total_score > 0 else "Safe",
            delta_color=color
        )

        # 2. PASSIVE ANALYSIS (Headers & SSL)
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("🌐 Security Headers")
            st.json(data.get('headers', {}))
        with col2:
            st.subheader("🔒 SSL/TLS Status")
            ssl = data.get('ssl_info', {})
            st.info(f"Status: {ssl.get('status', 'Unknown')}")

        # 3. ACTIVE VULNERABILITY TABLE
        st.divider()
        st.subheader("🚀 Active Injection Results")
        vulns = data.get('vulnerabilities', [])

        if vulns:
            df = pd.DataFrame(vulns)
            # Reorder columns for better reading
            df = df[['type', 'severity', 'score', 'description']]

            # Style the table: Highlight the 'score' column
            st.dataframe(df.style.background_gradient(cmap='Reds', subset=['score']), use_container_width=True)
        else:
            st.success("Target passed all active SQLi/XSS injection tests.")
    else:
        st.error("No scan history found for this target URL.")