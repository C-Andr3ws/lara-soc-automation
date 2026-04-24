# Attack Scenarios

All five scenarios were executed within an isolated VMware lab environment. A Kali Linux VM generated attack traffic directed at a Windows 10 endpoint. No real-world systems or networks were involved at any point.

Each scenario was **pre-verified** to confirm correct detection before formal evaluation runs began. Timing and quality data were only collected once the pipeline was confirmed to be producing correct outputs for that scenario.

---

## Scenario 1 — Brute Force Authentication

**MITRE ATT&CK:** T1110 — Brute Force  
**Detection Source:** Windows Security Event Logs  
**Log:** Event ID 4625 (Failed Logon)

**How it was simulated:**  
Repeated failed SSH/RDP login attempts were generated from the Kali Linux VM targeting the Windows 10 endpoint. A Splunk SPL detection rule aggregated Event ID 4625 occurrences per source IP within a defined time window, triggering an alert when the count exceeded a configured threshold.

**Why it was selected:**  
Brute force is one of the most common alert types in real SOC environments. It also involves an external source IP, making it suitable for AbuseIPDB enrichment — allowing direct comparison between LLM-only (no IP validation) and fully integrated (IP reputation checked) configurations.

**Pipeline configurations tested:** A (Manual), B (LLM-Only), C (Fully Integrated)

---

## Scenario 2 — Malicious File Execution (File Hash Detection)

**MITRE ATT&CK:** T1059 / T1204 — User Execution / Command and Scripting  
**Detection Source:** Sysmon  
**Log:** Sysmon Event ID 1 (Process Creation)

**How it was simulated:**  
A known-malicious process was executed on the Windows endpoint, captured by Sysmon with full SHA256 hash values. Two sub-scenarios were run:
- A legitimate process (`splunk-admon.exe`) — expected LOW severity, monitoring only
- A known malware sample (DarkComet) — 67/72 VirusTotal detections, expected CRITICAL severity with isolation guidance

**Why it was selected:**  
File hash detection exercises VirusTotal enrichment directly. The two sub-scenarios (clean vs malicious) test whether the pipeline correctly differentiates based on threat intelligence data rather than just log characteristics.

**Pipeline configurations tested:** A (Manual), B (LLM-Only), C (Fully Integrated)

---

## Scenario 3 — Suspicious Network Scanning / IP Activity

**MITRE ATT&CK:** T1071 — Application Layer Protocol  
**Detection Source:** Network logs, Windows Firewall  
**Log:** Firewall connection attempts, Sysmon network events

**How it was simulated:**  
Port scanning activity was directed at the Windows endpoint targeting ports 135, 139, and 445 (common Windows service ports). The source IP was a known-malicious address (confirmed via AbuseIPDB) injected into the scenario to simulate realistic external threat activity, since all VMs are on a local private network.

**Note on IP simulation:**  
Because all lab machines use private IP ranges (192.168.x.x), known malicious IPs from public threat intelligence databases were manually substituted into the alert payload for enrichment testing. This is a standard limitation of isolated lab environments and is documented in the dissertation methodology.

**Pipeline configurations tested:** A (Manual), B (LLM-Only), C (Fully Integrated)

---

## Scenario 4 — Privilege Escalation

**MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation  
**Detection Source:** Windows Security Event Logs  
**Log:** Event ID 4720 (User Account Created), Event ID 4672 (Special Privileges Assigned)

**How it was simulated:**  
A new administrative account was created outside of expected operational patterns, followed by the assignment of special privileges — simulating post-compromise persistence and privilege escalation behaviour. This was triggered manually on the Windows endpoint.

**Why it was selected:**  
Privilege escalation is a high-severity, post-compromise behaviour. It does not involve external IP indicators or file hashes, so AbuseIPDB and VirusTotal are not invoked. This scenario was **excluded from Pipeline B** testing — evaluating LLM-only performance on this scenario would not produce a meaningfully different result from Pipeline C (since no enrichment tools would be called anyway).

**Pipeline configurations tested:** A (Manual), C (Fully Integrated)

---

## Scenario 5 — PowerShell-Based Attack

**MITRE ATT&CK:** T1059.001 — PowerShell  
**Detection Source:** Sysmon  
**Log:** Sysmon Event ID 1 with command-line arguments

**How it was simulated:**  
A PowerShell command using obfuscation techniques (encoded commands, `-EncodedCommand`, `IEX` invocation) was executed on the Windows endpoint. Sysmon captured the full command-line arguments, which were forwarded to Splunk and detected via a rule filtering for suspicious parent process / command-line patterns.

**Why it was selected:**  
PowerShell abuse is extremely prevalent in real SOC environments. Encoded PowerShell commands are a classic evasion technique that exercises the LLM's ability to interpret obfuscated commands and generate relevant deobfuscation and containment recommendations.

**Pipeline configurations tested:** A (Manual), C (Fully Integrated)

---

## Detection Rules Summary

| Scenario | Event ID(s) | Log Source | Detection Logic |
|---|---|---|---|
| Brute Force | 4625 | Windows Security | Failed logons per IP > threshold in time window |
| File Hash | Sysmon EID 1 | Sysmon | Process creation with hash extraction |
| Network Scanning | Firewall / Sysmon | Network | Connection attempts to ports 135/139/445 |
| Privilege Escalation | 4720, 4672 | Windows Security | Account creation + privilege assignment |
| PowerShell | Sysmon EID 1 | Sysmon | Suspicious command-line / encoded commands |

---

## Evaluation Coverage

| Scenario | Pipeline A (Manual) | Pipeline B (LLM-Only) | Pipeline C (Integrated) |
|---|---|---|---|
| Brute Force | ✅ | ✅ | ✅ |
| File Hash | ✅ | ✅ | ✅ |
| Network Scanning | ✅ | ✅ | ✅ |
| Privilege Escalation | ✅ | ❌ | ✅ |
| PowerShell | ✅ | ❌ | ✅ |

Pipeline B excluded Privilege Escalation and PowerShell scenarios because neither involves external IP indicators or file hashes — AbuseIPDB and VirusTotal provide no enrichment for these alert types. Evaluating Pipeline B against them would not produce a meaningfully distinct comparison point.
