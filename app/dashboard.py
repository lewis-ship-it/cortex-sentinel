import streamlit as st
import pandas as pd
from core.database import DatabaseManager

# Initialize Database
db = DatabaseManager()

st.set_page_config(page_title="Cortex Sentinel Dashboard", layout="wide")

st.title("🛡️ Cortex Sentinel: Security Report")
st.markdown("### Advanced Web Security Scanner Platform")

# Sidebar for controls
st.sidebar.header("Scan Controls")
target_url = st.sidebar.text_input("Enter Target URL", "https://example.com")

if st.sidebar.button("Fetch Latest Report"):
    # Cost Optimization: Fetching existing results instead of re-scanning
    data = db.get_cached_result(target_url)
    
    if data:
        st.success(f"Showing report for: {data['url']}")
        
        # Layout: Two columns for Passive Analysis
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🌐 Security Headers")
            headers = data.get('headers', {})
            st.json(headers) # Displays CSP, HSTS, etc. [cite: 9]

        with col2:
            st.subheader("🔒 SSL/TLS Status")
            ssl_info = data.get('ssl_info', {})
            st.write(f"Status: {ssl_info.get('status', 'Unknown')}")
            st.write(f"Details: {ssl_info.get('details', 'N/A')}")

        # Active Scanning Results
        st.divider()
        st.subheader("🚀 Active Vulnerability Detection")
        vulns = data.get('vulnerabilities', [])
        
        if vulns:
            df = pd.DataFrame(vulns)
            # Apply Severity Scoring 
            st.table(df)
        else:
            st.info("No active vulnerabilities (SQLi/XSS) detected in the last scan.")
            
    else:
        st.warning("No scan data found for this URL in the database.")

# Placeholder for Future Expansion [cite: 20]
st.sidebar.divider()
st.sidebar.info("Future Expansion: AI-based detection & Bug bounty integration.")