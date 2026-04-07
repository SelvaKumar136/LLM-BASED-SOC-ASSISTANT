"""
🛡️ AI SOC Assistant — Premium Dashboard
Streamlit-based interface with dark theme, glassmorphism design,
real-time investigation pipeline, and interactive alert management.
"""

import streamlit as st
import json
import time
from datetime import datetime
from ingest.normalizer import normalize_alert
from agents.supervisor import run_investigation
from hitl.approval_queue import get_pending_actions, approve_action, deny_action

# ---------------------------------------------------------------------------
# Page config & custom styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="AI SOC Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    /* ---- Dark theme overrides ---- */
    .stApp {
        background: linear-gradient(135deg, #0a0a1a 0%, #101030 50%, #0a0a1a 100%);
    }

    /* ---- Header styling ---- */
    .main-header {
        background: linear-gradient(135deg, rgba(99,102,241,0.15), rgba(139,92,246,0.10));
        border: 1px solid rgba(99,102,241,0.25);
        border-radius: 16px;
        padding: 1.5rem 2rem;
        margin-bottom: 1.5rem;
        backdrop-filter: blur(20px);
    }
    .main-header h1 {
        background: linear-gradient(135deg, #818cf8, #a78bfa, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2rem;
        font-weight: 800;
        margin: 0;
    }
    .main-header p {
        color: #a5b4fc;
        margin: 0.25rem 0 0 0;
        font-size: 0.95rem;
    }

    /* ---- Glass cards ---- */
    .glass-card {
        background: rgba(30, 30, 60, 0.6);
        border: 1px solid rgba(99,102,241,0.2);
        border-radius: 12px;
        padding: 1.25rem;
        margin-bottom: 1rem;
        backdrop-filter: blur(12px);
    }

    /* ---- Severity badges ---- */
    .badge {
        display: inline-block;
        padding: 4px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.8rem;
        letter-spacing: 0.5px;
    }
    .badge-critical { background: #dc2626; color: #fff; }
    .badge-high     { background: #ea580c; color: #fff; }
    .badge-medium   { background: #d97706; color: #fff; }
    .badge-low      { background: #16a34a; color: #fff; }

    /* ---- Metric cards ---- */
    .metric-card {
        background: linear-gradient(135deg, rgba(30,30,60,0.8), rgba(50,50,80,0.6));
        border: 1px solid rgba(99,102,241,0.15);
        border-radius: 12px;
        padding: 1rem 1.25rem;
        text-align: center;
    }
    .metric-card .value {
        font-size: 2rem;
        font-weight: 800;
        background: linear-gradient(135deg, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .metric-card .label {
        color: #94a3b8;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 0.25rem;
    }

    /* ---- Pipeline steps ---- */
    .pipeline-step {
        display: inline-block;
        padding: 6px 16px;
        border-radius: 8px;
        margin: 0 4px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    .step-active   { background: #4f46e5; color: #fff; animation: pulse 1.5s infinite; }
    .step-done     { background: #16a34a; color: #fff; }
    .step-pending  { background: rgba(100,100,140,0.3); color: #64748b; }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50%      { opacity: 0.6; }
    }

    /* ---- Threat category tag ---- */
    .threat-tag {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 8px;
        background: rgba(99,102,241,0.2);
        border: 1px solid rgba(99,102,241,0.3);
        color: #a5b4fc;
        font-weight: 600;
        font-size: 0.85rem;
    }

    /* ---- MITRE tag ---- */
    .mitre-tag {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 8px;
        background: rgba(234,88,12,0.15);
        border: 1px solid rgba(234,88,12,0.3);
        color: #fb923c;
        font-weight: 600;
        font-size: 0.85rem;
    }

    /* ---- Sidebar styling ---- */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, rgba(15,15,35,0.95), rgba(10,10,25,0.98));
        border-right: 1px solid rgba(99,102,241,0.15);
    }

    /* ---- Tab styling ---- */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background: rgba(30,30,60,0.5);
        border-radius: 8px;
        border: 1px solid rgba(99,102,241,0.15);
        color: #94a3b8;
    }
    .stTabs [aria-selected="true"] {
        background: rgba(99,102,241,0.2) !important;
        border-color: rgba(99,102,241,0.4) !important;
        color: #a5b4fc !important;
    }

    /* ---- Form styling ---- */
    .stTextInput > div > div {
        background: rgba(30,30,60,0.6);
        border: 1px solid rgba(99,102,241,0.2);
        border-radius: 8px;
    }
    .stSelectbox > div > div {
        background: rgba(30,30,60,0.6);
        border: 1px solid rgba(99,102,241,0.2);
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
if "alert_history" not in st.session_state:
    st.session_state.alert_history = []
if "last_result" not in st.session_state:
    st.session_state.last_result = None

# ---------------------------------------------------------------------------
# Pre-built alert scenarios
# ---------------------------------------------------------------------------
SCENARIOS = {
    "🔴 Mimikatz Credential Dump": {
        "title": "Mimikatz Execution Detected",
        "src_ip": "185.220.101.5",
        "hostname": "DESKTOP-HR-04",
        "username": "jsmith",
        "process_name": "mimikatz.exe",
    },
    "🟠 Ransomware Encryption": {
        "title": "Ransomware File Encryption Activity",
        "src_ip": "203.0.113.42",
        "hostname": "SRV-DB-02",
        "username": "svc_backup",
        "process_name": "svchost.exe",
    },
    "🟠 Cobalt Strike Beacon": {
        "title": "Cobalt Strike C2 Beacon Detected",
        "src_ip": "91.219.236.222",
        "hostname": "WS-FIN-07",
        "username": "mary.jones",
        "process_name": "rundll32.exe",
    },
    "🟡 Brute Force SSH": {
        "title": "Multiple Failed SSH Login Attempts",
        "src_ip": "45.33.32.156",
        "hostname": "SRV-WEB-03",
        "username": "root",
        "process_name": "sshd",
    },
    "🟡 Suspicious PowerShell": {
        "title": "Encoded PowerShell Command Execution",
        "src_ip": "10.0.1.22",
        "hostname": "LAPTOP-IT-12",
        "username": "admin",
        "process_name": "powershell.exe",
    },
    "🟢 Nmap Reconnaissance Scan": {
        "title": "Port Scanning Activity Detected",
        "src_ip": "198.51.100.23",
        "hostname": "SRV-DC-01",
        "username": "N/A",
        "process_name": "N/A",
    },
    "🔵 Custom Alert (Manual)": None,
}


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown("""
<div class="main-header">
    <h1>🛡️ AI SOC Assistant</h1>
    <p>Autonomous threat triage, investigation & response powered by LLM multi-agent pipeline</p>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Metrics row
# ---------------------------------------------------------------------------
history = st.session_state.alert_history
total = len(history)
critical_count = sum(1 for a in history if a.get("triage", {}).get("severity") == "Critical")
high_count = sum(1 for a in history if a.get("triage", {}).get("severity") == "High")
fp_count = sum(1 for a in history if a.get("triage", {}).get("false_positive") is True)

m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    st.markdown(f'<div class="metric-card"><div class="value">{total}</div><div class="label">Alerts Processed</div></div>', unsafe_allow_html=True)
with m2:
    st.markdown(f'<div class="metric-card"><div class="value">{critical_count}</div><div class="label">Critical</div></div>', unsafe_allow_html=True)
with m3:
    st.markdown(f'<div class="metric-card"><div class="value">{high_count}</div><div class="label">High</div></div>', unsafe_allow_html=True)
with m4:
    st.markdown(f'<div class="metric-card"><div class="value">{fp_count}</div><div class="label">False Positives</div></div>', unsafe_allow_html=True)
with m5:
    pending = len(get_pending_actions())
    st.markdown(f'<div class="metric-card"><div class="value">{pending}</div><div class="label">Pending Actions</div></div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar — Pending HITL Actions
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⏳ Pending Actions")
    actions = get_pending_actions()
    if not actions:
        st.success("✅ No pending actions")
    else:
        for i, action in enumerate(actions):
            with st.expander(f"🚨 {action.get('action_type', 'Unknown')}", expanded=True):
                st.json(action)
                c1, c2 = st.columns(2)
                if c1.button("✅ Approve", key=f"approve_{i}"):
                    approve_action(i)
                    st.rerun()
                if c2.button("🚫 Deny", key=f"deny_{i}"):
                    deny_action(i)
                    st.rerun()

    st.markdown("---")
    st.markdown("### 📊 Session Stats")
    if history:
        categories = {}
        for a in history:
            cat = a.get("triage", {}).get("threat_category", "Unknown")
            categories[cat] = categories.get(cat, 0) + 1
        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            st.markdown(f"- **{cat}**: {count}")
    else:
        st.caption("No alerts processed yet.")

    st.markdown("---")
    st.markdown("### 🏗️ Architecture")
    st.caption("LangGraph Multi-Agent Pipeline")
    st.code("Triage → Investigate → Respond → Memory", language=None)
    st.caption("Tools: VirusTotal · AbuseIPDB · SIEM · ChromaDB")

# ---------------------------------------------------------------------------
# Main — Alert Simulation
# ---------------------------------------------------------------------------
st.markdown("### 🚨 Simulate Security Alert")

scenario = st.selectbox(
    "Choose a threat scenario",
    list(SCENARIOS.keys()),
    index=0,
    key="scenario_select",
)

selected = SCENARIOS[scenario]

with st.form("alert_form", clear_on_submit=False):
    c1, c2 = st.columns(2)
    with c1:
        title = st.text_input(
            "Alert Title",
            value=selected["title"] if selected else "Custom Alert",
            key="f_title",
        )
        src_ip = st.text_input(
            "Source IP",
            value=selected["src_ip"] if selected else "",
            key="f_ip",
        )
        hostname = st.text_input(
            "Hostname",
            value=selected["hostname"] if selected else "",
            key="f_host",
        )
    with c2:
        username = st.text_input(
            "Username",
            value=selected["username"] if selected else "",
            key="f_user",
        )
        process = st.text_input(
            "Process Name",
            value=selected["process_name"] if selected else "",
            key="f_proc",
        )

    submitted = st.form_submit_button("🚀 Run AI Investigation", use_container_width=True)

# ---------------------------------------------------------------------------
# Investigation execution
# ---------------------------------------------------------------------------
if submitted:
    raw_data = {
        "title": title,
        "src_ip": src_ip,
        "hostname": hostname,
        "username": username,
        "process_name": process,
    }

    # Pipeline status display
    status_container = st.container()
    with status_container:
        st.markdown("""
        <div class="glass-card" style="text-align:center; padding: 1rem;">
            <span class="pipeline-step step-active">🔍 TRIAGE</span>
            <span style="color:#475569;"> → </span>
            <span class="pipeline-step step-pending">🔎 INVESTIGATE</span>
            <span style="color:#475569;"> → </span>
            <span class="pipeline-step step-pending">🛡️ RESPOND</span>
            <span style="color:#475569;"> → </span>
            <span class="pipeline-step step-pending">💾 MEMORY</span>
        </div>
        """, unsafe_allow_html=True)

    with st.spinner("🕵️ AI agents are investigating..."):
        normalized = normalize_alert("dashboard", raw_data)
        result = run_investigation(normalized)

    # Store in session state, then rerun so sidebar picks up pending actions
    st.session_state.alert_history.append(result)
    st.session_state.last_result = result
    st.rerun()

# ---------------------------------------------------------------------------
# Display last investigation result (after rerun)
# ---------------------------------------------------------------------------
if st.session_state.last_result is not None:
    result = st.session_state.last_result

    st.markdown("""
    <div class="glass-card" style="text-align:center; padding: 1rem;">
        <span class="pipeline-step step-done">🔍 TRIAGE</span>
        <span style="color:#475569;"> → </span>
        <span class="pipeline-step step-done">🔎 INVESTIGATE</span>
        <span style="color:#475569;"> → </span>
        <span class="pipeline-step step-done">🛡️ RESPOND</span>
        <span style="color:#475569;"> → </span>
        <span class="pipeline-step step-done">💾 MEMORY</span>
    </div>
    """, unsafe_allow_html=True)

    st.success("✅ Investigation Complete!")

    # Results tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔍 Triage Classification",
        "🔎 Investigation Report",
        "🛡️ Response Actions",
        "📋 Raw Data",
    ])

    with tab1:
        triage = result.get("triage", {})
        severity = triage.get("severity", "Medium")
        badge_class = f"badge-{severity.lower()}"

        st.markdown(f"""
        <div class="glass-card">
            <h4 style="color:#e2e8f0; margin-top:0;">Threat Classification</h4>
            <p><span class="badge {badge_class}">{severity.upper()}</span>
               <span class="threat-tag" style="margin-left:8px;">{triage.get('threat_category', 'Unknown')}</span>
               <span class="mitre-tag" style="margin-left:8px;">🎯 {triage.get('mitre_technique', 'N/A')}</span></p>
            <p style="color:#94a3b8; margin-top:12px;"><strong style="color:#cbd5e1;">MITRE Tactic:</strong> {triage.get('mitre_tactic', 'N/A')}</p>
            <p style="color:#94a3b8;"><strong style="color:#cbd5e1;">Reasoning:</strong> {triage.get('reasoning', 'N/A')}</p>
            <p style="color:#94a3b8;"><strong style="color:#cbd5e1;">IOC Summary:</strong> {triage.get('ioc_summary', 'N/A')}</p>
            <p style="color:#94a3b8;"><strong style="color:#cbd5e1;">False Positive:</strong> {'Yes' if triage.get('false_positive') else 'No'}
               (confidence: {triage.get('fp_confidence', 0):.0%})</p>
            <p style="color:#94a3b8;"><strong style="color:#cbd5e1;">Classification Confidence:</strong> {triage.get('category_confidence', 0):.0%}</p>
        </div>
        """, unsafe_allow_html=True)

    with tab2:
        investigation = result.get("investigation", "No investigation data.")
        st.markdown(f"""<div class="glass-card">
            <h4 style="color:#e2e8f0; margin-top:0;">🔎 Investigation Report</h4>
        </div>""", unsafe_allow_html=True)
        st.markdown(investigation)

    with tab3:
        response = result.get("response", "No response data.")
        st.markdown(f"""<div class="glass-card">
            <h4 style="color:#e2e8f0; margin-top:0;">🛡️ Response Actions</h4>
        </div>""", unsafe_allow_html=True)
        st.markdown(response)

        # Check for new pending actions
        new_actions = get_pending_actions()
        if new_actions:
            st.warning(f"⚠️ {len(new_actions)} action(s) require human approval — check sidebar")

    with tab4:
        st.json(result)

    # Clear last result button
    if st.button("🔄 Clear results & start new investigation"):
        st.session_state.last_result = None
        st.rerun()

# ---------------------------------------------------------------------------
# Alert History
# ---------------------------------------------------------------------------
if st.session_state.alert_history:
    st.markdown("---")
    st.markdown("### 📜 Alert History")

    for idx, record in enumerate(reversed(st.session_state.alert_history)):
        triage = record.get("triage", {})
        alert = record.get("alert", {})
        severity = triage.get("severity", "?")
        badge_class = f"badge-{severity.lower()}" if severity.lower() in ["critical", "high", "medium", "low"] else "badge-medium"

        with st.expander(
            f"{'🔴' if severity == 'Critical' else '🟠' if severity == 'High' else '🟡' if severity == 'Medium' else '🟢'} "
            f"{alert.get('title', 'Unknown')} — {severity} | {triage.get('threat_category', 'N/A')}",
            expanded=False,
        ):
            c1, c2, c3 = st.columns(3)
            c1.metric("Severity", severity)
            c2.metric("Category", triage.get("threat_category", "N/A"))
            c3.metric("MITRE", triage.get("mitre_technique", "N/A"))

            st.markdown(f"**Reasoning:** {triage.get('reasoning', 'N/A')}")
            st.markdown(f"**Response:** {record.get('response', 'N/A')[:300]}...")