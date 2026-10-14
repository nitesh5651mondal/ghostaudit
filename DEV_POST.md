# GhostAudit: The Air-Gapped Cyber Incident Forensics Copilot

_This is a submission for the [MLH x DEV Writing Challenge](https://dev.to/mlh-hackathon)_

<!-- Make sure you're signed in to DEV with the MLH account linked to your hackathon registration! -->

---

## What I Built

### The 3:00 AM Incident: When Cloud AI is Banned
Picture this nightmare scenario: It is 3:14 AM on a weekend. Your pager alerts scream. A core authentication service is failing across multiple availability zones, user sessions are dropping, and your syslog stream is flooded with unhandled database syntax warnings and suspicious payload executions.

You need immediate cognitive forensics. Naturally, the temptation is to copy-paste the stack trace into a cloud LLM like ChatGPT or Claude. But then your company's CISO guidelines echo:

> **"Never paste proprietary stack traces, client tokens, or company source code into third-party cloud LLMs. That is an immediate corporate and legal compliance violation."**

Cloud LLMs retain prompts, log context across remote nodes, and present an unacceptable risk of intellectual property and secret leakage during real-world breaches. Yet, diagnosing complex CVEs manually under pressure takes hours, leaving organizations vulnerable to lateral movement.

### The Solution: GhostAudit
To solve this data sovereignty paradox, I built **GhostAudit** — an air-gapped, multi-agent autonomous security and supply-chain incident forensics copilot powered by **Google Gemma**.

GhostAudit operates with **Zero Egress**: it executes 100% locally within your machine or private VPC. When an incident occurs, it ingests raw crash logs and affected repository files, scrubs any exposed credentials via a local Pre-Inference Sanitizer, and orchestrates three specialized Gemma agents inspired by classical myth to diagnose, classify, and generate a surgical git patch in seconds:

```
       [ Raw Crash Telemetry + Suspect Code ]
                         │
                         ▼
      [ 🔒 Pre-Inference Zero-Trust Sanitizer ]
                         │
                         ▼
        [ 👁️ Agent 1: ARGUS (Log Detective) ]
                         │
                         ▼
      [ 🛡️ Agent 2: CERBERUS (Code Gatekeeper) ]
                         │
                         ▼
     [ ⚡ Agent 3: PROMETHEUS (Patch Synthesizer) ]
                         │
                         ▼
    [ Unified Git Patch + CISO Post-Mortem Report ]
```

### The Tri-Agent Gemma Architecture
1. **👁️ Argus (The All-Seeing Log Observer)**: Ingests raw syslog, Docker traces, and crash dumps. Argus isolates the exact microsecond anomaly timestamp, uncovers injected exploitation payloads (e.g. `' OR '1'='1`), and pinpoints the culprit file and line number.
2. **🛡️ Cerberus (The Security & Code Gatekeeper)**: Audits the suspect repository code around Argus's culprit location. Cerberus classifies the flaw into formal **MITRE CWE standards** (such as CWE-89 SQL Injection, CWE-502 Insecure Deserialization, or CWE-918 SSRF), calculates an objective **CVSS v3.1** severity rating, and checks for exposed secrets.
3. **⚡ Prometheus (The Healer & Patch Synthesizer)**: Autonomously synthesizes a production-ready **Unified Git Diff (`.patch`)** that neutralizes the vulnerability without breaking API contracts, alongside defense-in-depth architectural hardening steps.

---

## Demo

### 🌐 Live CyberX-Inspired Operations Dashboard
- **Live Deployed App (Vercel):** [https://ghostaudit.vercel.app](https://ghostaudit.vercel.app) *(Replace with your live URL)*
- **GitHub Repository:** [https://github.com/your-username/ghostaudit](https://github.com/your-username/ghostaudit)

### Key Capabilities in the Console
1. **Interactive Radial Risk Proximity Radar Map**: Features animated counter-rotating orbital rings and live pulsing threat clusters inspired by modern cyber-operations platforms (CyberX). The central HUD dynamically recalculates critical assets and CVSS scores as new incidents are triaged.
2. **"Execute Tri-Agent Triage in One Go"**: Runs the complete chain (Pre-Inference Sanitizer $\to$ Argus $\to$ Cerberus $\to$ Prometheus) with a single click.
3. **Multi-View Security Suite**:
   - **Exposure Analysis**: Interactive risk mapping, preset breach scenarios, and dual custom code/telemetry ingestion textboxes.
   - **Incident Dashboard**: System-wide telemetry metrics (14 nodes, 1.42 GB ingested, 318 redacted secrets) and historical incident logs.
   - **Attack Path Graph**: Visual 4-hop kill-chain inspector (Untrusted Client $\to$ Gateway $\to$ Vulnerable Service $\to$ Core Database).
   - **Telemetry Feeds**: Real-time streaming syslog console with live search, severity filtering, and 1-click piping to Gemma.
4. **CISO Post-Mortem Export**: Downloadable markdown reports formatted for enterprise incident response reviews with validated unified git patches.

---

## Partner Technologies

### Google Gemma (Open-Weight Model Family)
For this project, **Google Gemma** was not an optional add-on — **it is the architectural foundation of the entire system**. 

#### How I Implemented Gemma:
- **Local Inference via Ollama & Python Engine**: I utilized `gemma2:2b` and `gemma2:9b` served locally on consumer hardware through Ollama and a Python orchestration bridge (`ghostaudit.core.engine`).
- **Prompt Specialization & Role Decomposition**: Rather than overloading a single prompt, I engineered distinct system personas:
  - *Argus* is conditioned specifically on stack trace syntax and anomaly detection.
  - *Cerberus* is conditioned on MITRE CWE classifications and CVSS v3.1 scoring formulas.
  - *Prometheus* is constrained to valid unified git diff syntax (`--- a/` and `+++ b/`).
- **Dual-Engine Resilience**: To guarantee judges and evaluators have a smooth experience regardless of their hardware or GPU access, I engineered an intelligent internal fallback mechanism that simulates the exact deterministic agent outputs if local Ollama models are still downloading.

#### My Experience Working with Gemma:
Working with Gemma 2 was eye-opening. For cybersecurity tasks, privacy is non-negotiable. Traditional wisdom assumed that code auditing required 70B+ parameter cloud models. Gemma proved that a compact, open-weight 2B or 9B parameter model running locally can achieve remarkable syntactic precision, spot malicious input concatenation in SQL statements, and generate clean, valid git diffs with negligible latency and zero token costs.

---

## Hackathon Experience

Building GhostAudit for this challenge was an exhilarating experience. 

What made this hackathon stand out was the constraint-driven innovation: **How do you make cutting-edge AI truly enterprise-ready without compromising on user privacy or data sovereignty?** 

Tackling this problem pushed me to think like both a developer and a security architect. I didn't just want to create another generic chat interface; I wanted to build something that feels like an authentic SecOps mission control center. Integrating the CyberX-inspired radial proximity radar, connecting the multi-agent pipeline, and watching Gemma autonomously isolate an SQL injection exploit and write a working `.patch` file at 3 AM made every line of code worthwhile.

Open-source AI belongs to developers. With tools like Google Gemma, we no longer have to choose between advanced cognitive intelligence and complete data privacy.
