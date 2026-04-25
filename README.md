# LARA — LLM-Assisted Response and Analysis
### AI-Augmented SOC Automation Pipeline | BEng (Hons) Cyber Security Dissertation Project

> **Splunk → n8n → GPT-4.1 Mini → AbuseIPDB + VirusTotal → DFIR-IRIS → Slack**

An end-to-end Security Operations Centre (SOC) automation pipeline that integrates a SIEM, SOAR platform, Large Language Model (LLM), external threat intelligence enrichment, automated case management, and real-time analyst notification — evaluated across three pipeline configurations with formal performance testing.

---

## Pipeline Architecture

![Incident Response Workflow](screenshots/incident-response-workflow.png)

---

## What makes this different

Most SOC automation lab projects demonstrate that a pipeline *works*. This project goes further by **formally evaluating whether it works better** — and by how much.

Three pipeline configurations were tested against five simulated attack scenarios across 15 controlled runs:

<table width="100%">
<thead><tr><th>Metric</th><th>Manual Baseline</th><th>LLM-Only</th><th>Fully Integrated</th></tr></thead>
<tbody>
<tr><td><strong>Avg. Triage Time</strong></td><td>209s</td><td>130s</td><td>38.1s</td></tr>
<tr><td><strong>Time Reduction</strong></td><td>—</td><td>↓ 38%</td><td>↓ 82%</td></tr>
<tr><td><strong>Action Quality</strong></td><td>3.0 / 5</td><td>4.0 / 5</td><td>4.57 / 5</td></tr>
<tr><td><strong>Context Quality</strong></td><td>3.6 / 5</td><td>3.0 / 5</td><td>4.29 / 5</td></tr>
<tr><td><strong>Analyst Steps</strong></td><td>6.6 avg</td><td>3.0 avg</td><td>3.6 avg</td></tr>
<tr><td><strong>Classification Accuracy</strong></td><td>100%</td><td>100%</td><td>100%</td></tr>
</tbody>
</table>

![Pipeline Comparison Radar](screenshots/pipeline-comparison-radar.png)

The central finding: **orchestration depth, not model capability alone, drives performance gains**. The LLM-only configuration improved speed and action quality but failed to improve contextual depth — because that requires external enrichment data, not just better reasoning.

> Full methodology, scoring rubric, per-attack-type breakdown, and interactive dashboard → [`results/`](results/)

---

## Pipeline in Action

### n8n Workflow Canvas
![n8n Workflow Canvas](screenshots/workflow-canvas.png)

### Slack Alert — Critical Severity
![Slack Notification](screenshots/slack-notification.png)

### DFIR-IRIS — Auto-Created Case
![DFIR-IRIS Case](screenshots/dfir-iris-case.png)

### DFIR-IRIS — Alert Queue
![DFIR-IRIS Cases List](screenshots/dfir-iris-cases-list.png)

---

## Lab Environment

Deployed across **5 Virtual Machines** in VMware Workstation Pro on an isolated internal network (`192.168.106.0/24`):

<table width="100%">
<thead><tr><th>VM</th><th>OS</th><th>Role</th><th>IP</th></tr></thead>
<tbody>
<tr><td>Windows Client</td><td>Windows 10 Pro</td><td>Endpoint telemetry source</td><td>192.168.106.128</td></tr>
<tr><td>Splunk Server</td><td>Ubuntu 24.04</td><td>SIEM platform</td><td>192.168.106.129</td></tr>
<tr><td>n8n Server</td><td>Ubuntu 24.04</td><td>SOAR & LLM orchestration</td><td>192.168.106.130</td></tr>
<tr><td>DFIR-IRIS Server</td><td>Ubuntu 24.04</td><td>Case management</td><td>192.168.106.131</td></tr>
<tr><td>Kali Linux</td><td>Kali Linux</td><td>Attack simulation</td><td>192.168.106.133</td></tr>
</tbody>
</table>

![VMware Lab Overview](screenshots/vmware-lab-overview.png)

![VMware Network Config](screenshots/vmware-network-config.png)

All attack traffic was generated within this isolated network. No real-world attack traffic was used at any point.

---

## Three Pipeline Configurations

### Pipeline A — Manual Baseline
Standard Tier 1 SOC analyst workflow with no automation. The analyst manually queries Splunk logs, consults AbuseIPDB and VirusTotal directly, assesses severity, documents findings, and initiates response actions. Establishes the performance baseline.

### Pipeline B — LLM-Only
Splunk alert is forwarded via webhook to n8n, which passes the structured alert to GPT-4.1 Mini for classification, severity assessment, and response recommendations. No external threat intelligence APIs are called. Isolates the contribution of LLM reasoning alone.

> Pipeline B was not a separate workflow — it was achieved by disabling the AbuseIPDB, VirusTotal, and VirusTotal-FileHash tool nodes in the same n8n workflow used for Pipeline C.

### Pipeline C — Fully Integrated (Primary)
Complete pipeline. LLM analysis is supplemented by real-time threat intelligence enrichment via AbuseIPDB (IP reputation) and VirusTotal (file hash and IP detection). Results are used to auto-create a case in DFIR-IRIS and deliver a formatted Slack notification for high and critical severity alerts only.

---

## Attack Scenarios

Five simulated attack scenarios mapped to MITRE ATT&CK techniques:

<table width="100%">
<thead><tr><th>Scenario</th><th>MITRE Technique</th><th>Detection Source</th></tr></thead>
<tbody>
<tr><td>Brute Force Authentication</td><td>T1110</td><td>Windows Event ID 4625</td></tr>
<tr><td>Malicious File Execution / Hash</td><td>T1059 / T1204</td><td>Sysmon Event ID 1</td></tr>
<tr><td>Suspicious IP / Network Scanning</td><td>T1046</td><td>Windows Firewall logs</td></tr>
<tr><td>Privilege Escalation / Admin Account</td><td>T1136 / T1078</td><td>Windows Event ID 4720 / 4732</td></tr>
<tr><td>PowerShell-Based Attack</td><td>T1059.001</td><td>Sysmon command-line telemetry</td></tr>
</tbody>
</table>

### Splunk Detection Rules

![Splunk Alerts List](screenshots/splunk-alerts.png)

![Splunk Brute Force Detection](screenshots/splunk-brute-force-detection.png)

![Splunk Admin Account Detection](screenshots/splunk-admin-detection.png)

### Endpoint Telemetry — Sysmon

![Sysmon Event Viewer](screenshots/sysmon-event-viewer.png)

All scenarios were pre-verified to ensure correct detection before formal timing tests began. The 100% classification accuracy result reflects performance under controlled conditions against known, tested scenarios — not a claim of generalised real-world reliability.

---

## Key Results — Explained

### Why LLM-Only had *fewer* analyst steps than Fully Integrated
Pipeline B (LLM-Only) recorded a mean of 3.0 analyst steps vs 3.6 for Pipeline C. This is **not** because it was more efficient — it is because it skipped enrichment steps entirely. Threat intelligence lookups for IP reputation and file hash validation were simply absent, reducing step count through omission rather than optimisation. Pipeline C automates those same steps, delivering both lower workload and higher analytical depth.

### Why accuracy was 100% across all three modes
Each attack scenario was tested and verified to produce correct detections before formal evaluation runs began. Timing and quality data were only collected once the pipeline was confirmed to be working correctly. The 100% accuracy result therefore reflects consistent performance under controlled laboratory conditions with pre-validated scenarios, not performance against novel or adversarial inputs.

### Why context quality dropped for LLM-Only
GPT-4.1 Mini is capable of strong reasoning, but it can only work with the data it receives. Without AbuseIPDB and VirusTotal enrichment, the model has no external validation of indicators — it can classify the *type* of attack from log data alone, but cannot confirm whether an IP address is genuinely malicious or a file hash is known malware. Context quality is determined by enrichment depth, not model capability.

---

## Limitations

This project is an **academic proof-of-concept** in a controlled laboratory environment. Real-world deployment would require addressing:

<table width="100%">
<thead><tr><th>Limitation</th><th>Detail</th></tr></thead>
<tbody>
<tr><td><strong>Cost</strong></td><td>OpenAI API and Splunk Enterprise are commercial. See alternatives below.</td></tr>
<tr><td><strong>Test scale</strong></td><td>15 runs across 5 scenarios — sufficient for comparative evaluation, not production validation</td></tr>
<tr><td><strong>Simulated attacks</strong></td><td>All attacks generated on a local VMware network, not real-world traffic</td></tr>
<tr><td><strong>Manual timing</strong></td><td>Stage timestamps recorded manually with stopwatch application</td></tr>
<tr><td><strong>API dependency</strong></td><td>AbuseIPDB and VirusTotal rate limits and availability not stress-tested</td></tr>
<tr><td><strong>Single researcher</strong></td><td>Qualitative scoring applied by one person; structured rubric used to reduce subjectivity</td></tr>
<tr><td><strong>LLM non-determinism</strong></td><td>GPT-4.1 Mini outputs are probabilistic — identical inputs can produce varied outputs</td></tr>
</tbody>
</table>

---

## Free & Open-Source Alternatives

This pipeline uses commercial tools. If you want to replicate it without cost, here are the alternatives evaluated in the dissertation:

### SIEM Alternatives to Splunk

<table width="100%">
<thead><tr><th>Tool</th><th>Type</th><th>Strengths</th><th>Limitations</th></tr></thead>
<tbody>
<tr><td><strong>Wazuh</strong></td><td>Open-source</td><td>Purpose-built for security, free, good community support</td><td>Smaller ecosystem, fewer out-of-box integrations</td></tr>
<tr><td><strong>ELK Stack</strong> (Elastic)</td><td>Open-source</td><td>Flexible, highly customisable, cost-effective</td><td>Requires significant expertise to configure and maintain</td></tr>
<tr><td><strong>Security Onion</strong></td><td>Open-source</td><td>Comprehensive network monitoring, training-friendly</td><td>Resource-heavy, limited scalability, on-premises only</td></tr>
<tr><td><strong>Microsoft Sentinel</strong></td><td>Cloud (Azure)</td><td>Scalable, low maintenance, integrates with Microsoft stack</td><td>Requires Azure, costs can escalate with data volume</td></tr>
</tbody>
</table>

### LLM Alternatives to GPT-4.1 Mini (OpenAI API)

<table width="100%">
<thead><tr><th>Model</th><th>Type</th><th>Cost</th><th>Privacy</th><th>Notes</th></tr></thead>
<tbody>
<tr><td><strong>Ollama + Mistral 7B</strong></td><td>Local / Open-source</td><td>Free</td><td>High — data stays local</td><td>Lightweight, fast, good for constrained environments</td></tr>
<tr><td><strong>Ollama + LLaMA</strong></td><td>Local / Open-source</td><td>Free</td><td>High — data stays local</td><td>Highly customisable, requires more hardware</td></tr>
<tr><td><strong>Claude (Anthropic)</strong></td><td>API / Proprietary</td><td>Medium–High</td><td>Moderate</td><td>Strong safety alignment, fewer n8n integration examples</td></tr>
<tr><td><strong>Google Gemini</strong></td><td>API / Proprietary</td><td>Medium</td><td>Moderate</td><td>Competitive reasoning capability</td></tr>
</tbody>
</table>

**For a fully free, privacy-preserving setup:** replace the OpenAI node in n8n with an Ollama HTTP request node pointing to a locally hosted model. Mistral 7B is a practical starting point — lower accuracy than GPT-4.1 Mini but no API costs and all data stays within your network.

### SOAR Alternatives to n8n

<table width="100%">
<thead><tr><th>Tool</th><th>Type</th><th>Notes</th></tr></thead>
<tbody>
<tr><td><strong>Shuffle</strong></td><td>Open-source</td><td>Purpose-built for security teams, growing integrations</td></tr>
<tr><td><strong>Splunk SOAR</strong></td><td>Commercial</td><td>Tight Splunk integration but expensive</td></tr>
<tr><td><strong>Cortex XSOAR</strong></td><td>Commercial</td><td>Feature-rich, very high cost</td></tr>
<tr><td><strong>StackStorm</strong></td><td>Open-source</td><td>Powerful but steep learning curve</td></tr>
</tbody>
</table>

---

## Repository Structure

```
lara-soc-automation/
├── README.md
├── LICENSE
├── env.example                         ← API key template
├── workflows/
│   └── pipeline-c.json                ← n8n workflow export (fully integrated)
│                                          Pipeline B = disable AbuseIPDB + VirusTotal nodes
│                                          Pipeline A = manual baseline, no automation
├── splunk/
│   └── detection-rules.md             ← All 5 SPL queries with explanation
├── results/
│   ├── README.md                       ← Methodology, scoring rubric, full findings
│   ├── evaluation-results.csv         ← All 15 test runs raw data
│   └── dashboard.html                 ← Interactive analysis dashboard (open locally)
├── screenshots/
│   ├── incident-response-workflow.png
│   ├── workflow-canvas.png
│   ├── pipeline-comparison-radar.png
│   ├── slack-notification.png
│   ├── dfir-iris-case.png
│   ├── dfir-iris-cases-list.png
│   ├── splunk-alerts.png
│   ├── splunk-brute-force-detection.png
│   ├── splunk-admin-detection.png
│   ├── sysmon-event-viewer.png
│   ├── lab-network-topology.png
│   ├── vmware-lab-overview.png
│   └── vmware-network-config.png
└── docs/
    ├── attack-scenarios.md
    ├── lab-environment.md
    └── prompts-and-code.md
```

---

## Setup Overview

> Full step-by-step instructions are in [`docs/lab-environment.md`](docs/lab-environment.md)

**Prerequisites:**
- VMware Workstation Pro (or VirtualBox)
- Ubuntu 24.04 ISOs × 3, Windows 10 Pro ISO × 1, Kali Linux ISO × 1
- Splunk Enterprise (trial or developer licence)
- Docker + Docker Compose (for n8n and DFIR-IRIS)
- API keys — see [`env.example`](env.example)

**Required API keys:**
- OpenAI API key (GPT-4.1 Mini) — or substitute a local Ollama model
- AbuseIPDB API key (free tier available)
- VirusTotal API key (free tier available)
- DFIR-IRIS API key (generated post-deployment)
- Slack Incoming Webhook URL

---

## Tech Stack

`Splunk` `n8n` `GPT-4.1 Mini` `AbuseIPDB` `VirusTotal` `DFIR-IRIS` `Slack` `VMware` `Docker` `Ubuntu 24.04` `Windows 10` `Kali Linux` `Sysmon` `JavaScript`

---

## Academic Context

This project was developed as an Honours Dissertation for a BEng (Hons) Cyber Security degree at the University of the West of Scotland (2025–2026). The system was designed, implemented, and formally evaluated as primary research — not a tutorial follow-along.

The dissertation examines orchestration depth as the primary driver of AI-assisted SOC performance, contributing a comparative evaluation framework that distinguishes between the independent contributions of LLM reasoning and external threat intelligence enrichment.

---

## Disclaimer

This project was built for academic research and educational purposes in a fully isolated lab environment. All attack scenarios were simulated within a local VMware network. No real systems, networks, or data were targeted or compromised at any point.

---

## Connect

**LinkedIn:** [Christopher Andrews](https://www.linkedin.com/in/christopher-andrews-958b30248/)  
