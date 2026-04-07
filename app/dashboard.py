import streamlit as st
import requests
import pandas as pd
import json
import plotly.express as px

from streamlit_agraph import agraph, Node, Edge, Config

# -------------------------
# CONFIG
# -------------------------
API_BASE = st.secrets.get("API_URL", "http://localhost:8000")
API_KEY = st.secrets.get("SENTINEL_API_KEY", "test-key-123")
HEADERS = {"x-api-key": API_KEY}

st.set_page_config(page_title="Sentinel AI | Command Center", layout="wide")
if st.button("📄 Generate PDF Report"):
    res = requests.get(f"{API_BASE}/report/pdf/{job_id}", headers=HEADERS)

    if res.status_code == 200:
        file_path = res.json()["file"]

        with open(file_path, "rb") as f:
            st.download_button(
                label="⬇️ Download Report",
                data=f,
                file_name="security_report.pdf",
                mime="application/pdf"
            )

# -------------------------
# STATE
# -------------------------
if "job_id" not in st.session_state:
    st.session_state.job_id = None
if "report" not in st.session_state:
    st.session_state.report = None
if "selected_node" not in st.session_state:
    st.session_state.selected_node = None

# -------------------------
# SIDEBAR
# -------------------------
with st.sidebar:
    st.title("🛡️ Sentinel AI")
    target = st.text_input("Target URL", "http://testphp.vulnweb.com")

    if st.button("🚀 Launch Scan"):
        res = requests.post(
            f"{API_BASE}/scan",
            json={"url": target},
            headers=HEADERS
        )
        if res.status_code == 200:
            st.session_state.job_id = res.json()["job_id"]
            st.session_state.report = None

# -------------------------
# MAIN
# -------------------------
if not st.session_state.job_id:
    st.info("Start a scan to view results.")
    st.stop()

job_id = st.session_state.job_id

# -------------------------
# FETCH REPORT
# -------------------------
try:
    res = requests.get(f"{API_BASE}/report/{job_id}", headers=HEADERS)
    if res.status_code == 200:
        st.session_state.report = res.json()["content"]
except:
    pass

report = st.session_state.report

if not report:
    st.warning("Scan running... waiting for report.")
    st.stop()

# -------------------------
# OVERVIEW
# -------------------------
st.title("🛰️ Security Command Center")

summary = report.get("summary", {})

c1, c2, c3, c4 = st.columns(4)
c1.metric("Findings", summary.get("validated_findings", 0))
c2.metric("Critical", summary.get("critical", 0))
c3.metric("High", summary.get("high", 0))
c4.metric("Chains", summary.get("chains_detected", 0))

# -------------------------
# TABS
# -------------------------
tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
    "📊 Risk",
    "🎯 Priority",
    "🔗 Chains",
    "🧠 Critical Paths",
    "🌐 Attack Graph",
    "📡 Live Feed",
    "📦 Code Audit",
    "⚙️ Raw"
])

# -------------------------
# TAB 1: RISK
# -------------------------
with tab1:
    findings = report.get("findings", [])
    if findings:
        df = pd.DataFrame(findings)
        fig = px.pie(df, names="severity", title="Risk Distribution")
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(df)

# -------------------------
# TAB 2: prioritization
# -------------------------
with tab2:
    st.subheader("🎯 Risk Prioritization")

    prioritized = report.get("prioritized", [])

    if not prioritized:
        st.info("No prioritized findings available")
    else:
        df = pd.DataFrame(prioritized)

        st.dataframe(df[[
            "type",
            "url",
            "severity",
            "priority_score",
            "fix_first"
        ]])

        # TOP RISK
        top = report.get("summary", {}).get("top_risk")

        if top:
            st.markdown("## 🚨 Fix This First")
            st.json(top)        

# -------------------------
# TAB 3: CHAINS
# -------------------------
with tab3:
    chains = report.get("chains", [])
    if not chains:
        st.info("No chains found")
    else:
        for i, chain in enumerate(chains):
            st.markdown(f"### Chain {i+1}")
            for step in chain:
                st.write(f"➡️ {step}")

# -------------------------
# TAB 4: CRITICAL PATHS
# -------------------------
with tab4:
    paths = report.get("critical_paths", [])
    if not paths:
        st.info("No critical paths")
    else:
        for p in paths:
            st.markdown("### ⚠️ Attack Path")
            st.write(p)

# -------------------------
# TAB 5: INTERACTIVE GRAPH
# -------------------------
with tab5:
    st.subheader("🌐 Interactive Attack Graph")

    graph = report.get("attack_graph", {})

    if not graph:
        st.info("No graph data available")
    else:
        # FILTER
        severity_filter = st.multiselect(
            "Filter by severity",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"]
        )

        nodes = []
        edges = []

        for node_id, data in graph.items():
            vuln = data["vuln"]
            severity = vuln.get("severity", "Low")

            if severity not in severity_filter:
                continue

            color = {
                "Critical": "red",
                "High": "orange",
                "Medium": "yellow",
                "Low": "green"
            }.get(severity, "gray")

            nodes.append(Node(
                id=node_id,
                label=vuln.get("type", "Vuln"),
                size=25,
                color=color
            ))

            for edge in data.get("edges", []):
                edges.append(Edge(source=node_id, target=edge["to"]))

        config = Config(
            width="100%",
            height=600,
            directed=True,
            physics=True,
            hierarchical=False
        )

        selected = agraph(nodes=nodes, edges=edges, config=config)

        # -------------------------
        # NODE DETAILS PANEL
        # -------------------------
        if selected:
            st.session_state.selected_node = selected

        if st.session_state.selected_node:
            node_data = graph.get(st.session_state.selected_node, {}).get("vuln", {})

            st.markdown("### 🔍 Vulnerability Details")
            st.json(node_data)
# -------------------------
# TAB 6: CODE AUDIT
# -------------------------
with tab7:
    st.subheader("📦 Static Code Analysis")

    uploaded_file = st.file_uploader("Upload ZIP", type=["zip"])

    if uploaded_file:
        with st.spinner("Analyzing code..."):
            files = {
                "file": (uploaded_file.name, uploaded_file, "application/zip")
            }

            res = requests.post(f"{API_BASE}/upload", files=files)

            if res.status_code == 200:
                data = res.json()
                findings = data.get("findings", [])
                path = data.get("path")

                st.success(f"Scan complete: {len(findings)} findings")

                if findings:
                    df = pd.DataFrame(findings)
                    st.dataframe(df)

                    selected_file = st.selectbox(
                        "Select file to view",
                        list(set(f.get("file") for f in findings))
                    )

                    if selected_file:
                        full_path = os.path.join(path, selected_file)

                        try:
                            with open(full_path, "r", errors="ignore") as f:
                                content = f.read()

                            st.code(content, language="python")

                        except Exception as e:
                            st.error(f"Cannot open file: {e}")
                else:
                    st.success("No issues found")

            else:
                st.error("Upload failed")

# -------------------------
# TAB 8: RAW
# -------------------------
with tab8:
    st.subheader("📡 Live Scan Feed")

    auto_refresh = st.checkbox("Auto refresh", True)

    logs_container = st.container()

    try:
        res = requests.get(f"{API_BASE}/logs/{job_id}", headers=HEADERS)

        if res.status_code == 200:
            logs = res.json()

            for log in logs:
                logs_container.write(f"{log['created_at']} - {log['message']}")

    except Exception as e:
        st.error(f"Log error: {e}")

    if auto_refresh:
        st.experimental_rerun()