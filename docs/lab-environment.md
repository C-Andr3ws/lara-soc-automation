# Lab Environment

## Overview

The LARA pipeline was deployed across five virtual machines running in VMware Workstation Pro on a single physical host. All machines operate on an isolated internal network — no traffic leaves the host machine.

This document covers the environment setup and network configuration. For full step-by-step installation instructions for each component, refer to the technical implementation guide.

---

## Virtual Machine Configuration

| VM | OS | Role | IP Address | RAM | Storage |
|---|---|---|---|---|---|
| Windows Client | Windows 10 Pro | Endpoint telemetry source + attack target | 192.168.106.128 | 4GB | 60GB |
| Splunk Server | Ubuntu 24.04 LTS | SIEM — log ingestion, detection, alerting | 192.168.106.129 | 4GB | 60GB |
| n8n Server | Ubuntu 24.04 LTS | SOAR — workflow orchestration + LLM calls | 192.168.106.130 | 4GB | 40GB |
| DFIR-IRIS Server | Ubuntu 24.04 LTS | Case management | 192.168.106.131 | 4GB | 40GB |
| Kali Linux | Kali Linux (rolling) | Attack simulation | 192.168.106.133 | 2GB | 40GB |

---

## Network Configuration

All VMs use **VMnet8** (NAT) in VMware, configured as `192.168.106.0/24` with static IP addresses assigned to each VM.

Static IP configuration prevents address changes between reboots, which is essential because all integration endpoints (webhook URLs, API base URLs) are hardcoded to specific IPs.

### Inter-Component Communication

| Source | Destination | Protocol | Purpose |
|---|---|---|---|
| Windows Client | Splunk Server :9997 | TCP | Universal Forwarder log shipping |
| Splunk Server | n8n Server :5678 | HTTP (webhook) | Alert forwarding on trigger |
| n8n Server | OpenAI API | HTTPS | LLM analysis requests |
| n8n Server | AbuseIPDB API | HTTPS | IP reputation queries |
| n8n Server | VirusTotal API | HTTPS | File hash + IP queries |
| n8n Server | DFIR-IRIS Server :443 | HTTPS | Automated case creation |
| n8n Server | Slack | HTTPS (webhook) | Analyst notifications |
| Kali Linux | Windows Client | Various | Simulated attack traffic |

---

## Component Deployment

### Splunk (SIEM)
- **Deployment:** Native installation on Ubuntu 24.04
- **Version:** Splunk Enterprise (trial licence)
- **Key config:** Custom index `chris-project`, Universal Forwarder on Windows client, Splunk Add-on for Microsoft Windows for field normalisation
- **Ingested sources:** Windows Security events, Sysmon operational logs, System/Application logs, Windows Firewall logs

### n8n (SOAR)
- **Deployment:** Docker + Docker Compose on Ubuntu 24.04
- **Access:** `http://192.168.106.130:5678`
- **Key config:** Configured to restart automatically on boot; credentials stored in n8n credential manager (not in workflow JSON)

### DFIR-IRIS (Case Management)
- **Deployment:** Docker + Docker Compose on Ubuntu 24.04
- **Access:** `https://192.168.106.131`
- **Key config:** API key generated post-deployment, stored in n8n credentials

### Sysmon (Endpoint Telemetry)
- **Deployment:** Installed on Windows 10 client
- **Purpose:** Extends native Windows logging with process creation (EID 1), network connections, file hash values
- **Config:** SwiftOnSecurity Sysmon config (community-maintained baseline)

---

## Replication Notes

### Minimum hardware requirements
This lab was run on a single physical machine. Recommended minimum:
- 16GB RAM (4GB per Ubuntu VM, 4GB Windows, 2GB Kali)
- 250GB free disk space
- Processor with virtualisation support enabled in BIOS

### Hypervisor alternatives
VMware Workstation Pro was used. Alternatives:
- **VirtualBox** (free) — same NAT networking concept, slightly different UI
- **Proxmox** (free, bare-metal) — better for dedicated lab hardware

### Licence considerations
- **Splunk Enterprise:** Requires a trial or developer licence. The trial expires — if you're building this long-term, apply for a Splunk developer licence or use Wazuh/ELK instead
- **n8n:** Self-hosted version is free with no restrictions
- **DFIR-IRIS:** Fully open-source, no licence required
- **OpenAI API:** Requires a paid account with credit. For a free alternative, use Ollama with a local model

### Ollama (free LLM alternative)
Install Ollama on the n8n server or a separate VM. Pull a model:
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull mistral
```
Then in n8n, replace the OpenAI node with an HTTP Request node pointing to:
```
http://localhost:11434/api/generate
```
No API key required. Mistral 7B is a good starting point — lower accuracy than GPT-4.1 Mini but completely free and private.
