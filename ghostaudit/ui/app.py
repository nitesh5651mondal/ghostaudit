"""
GhostAudit Interactive Forensics Console: Modern Streamlit Web Application
Features:
- Live multi-agent execution feed (Argus -> Cerberus -> Prometheus)
- Pre-inference secret redaction audit
- Vulnerability metrics (CVSS, CWE classification)
- Interactive git diff comparison
- Instant one-click CISO incident post-mortem report download
"""
import streamlit as st
import json
import time
from ghostaudit.core.orchestrator import GhostAuditOrchestrator
from ghostaudit.scenarios.data import SCENARIOS

# Page Configuration
st.set_page_config(
    page_title="GhostAudit // Air-Gapped Gemma Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Dark CSS
st.markdown("""
<style>
    .reportview-container {
        background: #0d1117;
    }
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .agent-header {
        font-family: 'Courier New', Courier, monospace;
        color: #58a6ff;
        font-weight: bold;
    }
    .badge-critical {
        background-color: #da3633;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-high {
        background-color: #d29922;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
st.sidebar.image("https://img.shields.io/badge/GhostAudit-Air--Gapped_Gemma_Copilot-7928CA?style=for-the-badge&logo=google&logoColor=white")
st.sidebar.title("🛡️ Mission Control")
st.sidebar.markdown("**GhostAudit** runs 100% locally on **Google Gemma** without leaking source code or credentials to external clouds.")

model_selection = st.sidebar.selectbox(
    "Select Gemma Variant:",
    ["gemma2:2b", "gemma2:9b", "gemma:2b", "codegemma:7b"],
    index=0
)

st.sidebar.markdown("---")
st.sidebar.subheader("🎯 Demo Incident Scenarios")
scenario_key = st.sidebar.selectbox(
    "Load Real-World Breach Scenario:",
    list(SCENARIOS.keys()),
    format_func=lambda k: SCENARIOS[k]["title"]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🏛️ Agent Architecture")
st.sidebar.markdown("👁️ **Argus**: Log & Crash Triage")
st.sidebar.markdown("🛡️ **Cerberus**: Security & Code Gatekeeper")
st.sidebar.markdown("⚡ **Prometheus**: Patch Synthesizer & Healer")

# Main Header
st.title("🛡️ GhostAudit: Autonomous Security Incident Forensics")
st.caption("Air-Gapped Supply-Chain & Zero-Day Incident Investigator Powered by Local Google Gemma")

# Input layout
col_left, col_right = st.columns(2)

selected_scenario = SCENARIOS[scenario_key]

with col_left:
    st.subheader("📋 Ingestion: Raw Telemetry & Logs")
    raw_logs = st.text_area(
        "Server / Crash / Docker Logs:",
        value=selected_scenario["logs"].strip(),
        height=240
    )

with col_right:
    st.subheader("💻 Suspect Source Code")
    source_code = st.text_area(
        "Affected Repository File:",
        value=selected_scenario["source"].strip(),
        height=240
    )

start_scan = st.button("🚀 INITIATE GHOSTAUDIT FORENSICS PIPELINE", type="primary", use_container_width=True)

if start_scan:
    orchestrator = GhostAuditOrchestrator(model_name=model_selection)

    with st.status("Executing Air-Gapped Investigation...", expanded=True) as status:
        st.write("🔒 **Step 1:** Running Pre-Inference Secret & PII Sanitizer...")
        time.sleep(0.3)
        st.write("👁️ **Step 2:** Activating **Argus** (Analyzing crash signatures & stack traces)...")
        time.sleep(0.4)
        st.write("🛡️ **Step 3:** Activating **Cerberus** (Auditing source code for CWE & secret exposure)...")
        time.sleep(0.4)
        st.write("⚡ **Step 4:** Activating **Prometheus** (Synthesizing unified git diff & defense plan)...")
        
        report = orchestrator.run_investigation(
            target_name=selected_scenario["title"],
            raw_logs=raw_logs,
            source_code=source_code
        )
        status.update(label=f"Forensics Complete! Incident ID: {report.incident_id}", state="complete", expanded=False)

    st.success(f"✅ Forensic Analysis Finished! Powered by {report.gemma_model_used}")

    # Top KPI Metrics
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("CVSS v3.1 Score", f"{report.cerberus.cvss_score} / 10.0")
    kpi2.metric("Severity", report.cerberus.severity.value)
    kpi3.metric("Redacted Secrets (Zero-Trust)", f"{report.sanitization_meta.redacted_secrets_count} items")
    kpi4.metric("Patch Verified Safe", "YES" if report.prometheus.patch_verified_safe else "NO")

    # Tabs for in-depth forensics
    tab_overview, tab_argus, tab_cerberus, tab_prometheus, tab_export = st.tabs([
        "📊 Executive Summary",
        "👁️ Argus (Telemetry)",
        "🛡️ Cerberus (Vulnerability)",
        "⚡ Prometheus (Git Patch)",
        "📄 Export CISO Report"
    ])

    with tab_overview:
        st.markdown(f"### 🎯 Incident Brief: {report.target_name}")
        st.info(report.executive_summary)
        
        st.markdown("#### 🔒 Pre-Inference Redaction Proof")
        st.write(f"GhostAudit scrubbed **{report.sanitization_meta.redacted_secrets_count}** sensitive patterns prior to model evaluation.")
        if report.sanitization_meta.redacted_items:
            st.json(report.sanitization_meta.redacted_items)
            
        with st.expander("View Sanitized Telemetry Feed"):
            st.code(report.sanitization_meta.sanitized_text, language="log")

    with tab_argus:
        st.markdown("### 👁️ Agent Argus: Log & Crash Detective")
        st.markdown(f"**Incident Classification:** `{report.argus.incident_type}`")
        st.markdown(f"**Culprit Location:** `{report.argus.stack_trace_culprit}`")
        st.markdown(f"**Root Cause Analysis:** {report.argus.root_cause_summary}")
        if report.argus.suspicious_payloads:
            st.markdown("**Detected Exploit Payloads:**")
            for p in report.argus.suspicious_payloads:
                st.code(p)
        st.caption(f"Reasoning: {report.argus.raw_reasoning}")

    with tab_cerberus:
        st.markdown("### 🛡️ Agent Cerberus: Security & Code Gatekeeper")
        st.markdown(f"**Formal Vulnerability:** `{report.cerberus.cwe_id}`")
        st.markdown(f"**Title:** {report.cerberus.vulnerability_title}")
        st.markdown(f"**Exploit Scenario:** {report.cerberus.exploit_scenario}")
        if report.cerberus.leaked_secrets_detected:
            st.warning("⚠️ **Secret Exposure Warnings:**")
            for sec in report.cerberus.leaked_secrets_detected:
                st.markdown(f"- {sec}")
        st.caption(f"Reasoning: {report.cerberus.raw_reasoning}")

    with tab_prometheus:
        st.markdown("### ⚡ Agent Prometheus: Patch Synthesizer & Healer")
        st.markdown("#### 🛠️ Production Unified Git Diff Patch")
        st.code(report.prometheus.git_patch_diff, language="diff")
        
        st.markdown("#### 📋 Remediation Steps")
        for step in report.prometheus.remediation_steps:
            st.markdown(f"- {step}")

        st.markdown("#### 🏰 Defense-in-Depth Hardening")
        for rec in report.prometheus.defense_in_depth_recommendations:
            st.markdown(f"- {rec}")

    with tab_export:
        st.markdown("### 📄 CISO-Ready Incident Post-Mortem Report")
        report_md = f"""# GHOSTAUDIT INCIDENT POST-MORTEM REPORT
**Incident ID:** {report.incident_id}  
**Timestamp:** {report.timestamp}  
**Engine:** {report.gemma_model_used}  
**Target:** {report.target_name}  

---
## 1. Executive Summary
{report.executive_summary}

## 2. Threat & Vulnerability Classification
- **CWE:** {report.cerberus.cwe_id}
- **Vulnerability Title:** {report.cerberus.vulnerability_title}
- **CVSS Base Score:** {report.cerberus.cvss_score} / 10.0 ({report.cerberus.severity.value})
- **Culprit Component:** {report.argus.stack_trace_culprit}

## 3. Telemetry & Log Findings (Argus)
- **Incident Type:** {report.argus.incident_type}
- **Root Cause Summary:** {report.argus.root_cause_summary}
- **Redacted Pre-Inference Tokens:** {report.sanitization_meta.redacted_secrets_count}

## 4. Remediation & Patch (Prometheus)
```diff
{report.prometheus.git_patch_diff}
```

### Remediation Checklist:
{chr(10).join(f"- [x] {s}" for s in report.prometheus.remediation_steps)}

### Defense-In-Depth Architecture:
{chr(10).join(f"- {d}" for d in report.prometheus.defense_in_depth_recommendations)}

---
*Generated autonomously and air-gapped by GhostAudit.*
"""
        st.download_button(
            label="💾 Download Official Incident Post-Mortem (Markdown)",
            data=report_md,
            file_name=f"{report.incident_id}_forensic_postmortem.md",
            mime="text/markdown"
        )
        st.markdown(report_md)
