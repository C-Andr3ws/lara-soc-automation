# Splunk Detection Rules

Five saved alerts configured in Splunk Enterprise under the `chris-project` index. All alerts are set to trigger a webhook to n8n when conditions are met. Screenshots of the alert list are in the `screenshots/` folder.

All alerts were disabled after testing to prevent repeated triggering during evaluation runs — this is reflected in the "Disabled" status shown in the Splunk alerts UI.

---

## Alert 1 — Admin Account Creation / Privilege Escalation

**MITRE ATT&CK:** T1136 (Create Account), T1078 (Valid Accounts)  
**Severity:** HIGH  
**Log Sources:** `WinEventLog:Security`  
**Event IDs:** 4720 (User Account Created), 4732 (Member Added to Security-Enabled Local Group)

**Detection Logic:**  
Triggers when a new user account is created (EID 4720) or when a user is added to the local Administrators group (EID 4732). Results are aggregated by `target_account` to capture both the account created and the user who initiated the change.

```spl
index=chris-project (source="WinEventLog:Security" OR sourcetype="WinEventLog:Security")
(EventCode=4720 OR EventCode=4732)
| eval action=case(
    EventCode=4720, "User Account Created",
    EventCode=4732, "Added to Local Administrators Group"
)
| eval raw_lc=lower(_raw)
| eval is_admin_add=if(EventCode=4732 AND match(raw_lc,"administrators"),1,0)
| where EventCode=4720 OR is_admin_add=1
| eval target_account=coalesce(Account_Name, TargetUserName, MemberName, "")
| eval initiating_user=coalesce(user, SubjectUserName, "")
| eval computer=coalesce(ComputerName, host)
| eval domain=coalesce(Account_Domain, SubjectDomainName, "")
| where target_account!="" AND target_account!="-"
| stats latest(_time) as Raw_Splunk_time
        values(action) as actions
        values(domain) as domain
        values(host) as host
        values(initiating_user) as initiating_user
        values(computer) as computer
        count as hits
        by target_account
| eval attack_type="Admin Account Creation / Privilege Escalation"
| eval mitre_technique="T1136,T1078"
| eval severity="HIGH"
| eval Raw_Splunk_time=strftime(Raw_Splunk_time,"%Y-%m-%d %H:%M:%S")
| table Raw_Splunk_time attack_type mitre_technique severity target_account initiating_user domain host computer actions hits
```

**Key fields passed to n8n:**
- `target_account` — the account that was created or added to admins
- `initiating_user` — the account that performed the action
- `actions` — what specifically happened (created / added to admins)
- `hits` — number of matching events

**LLM behaviour:**  
The system prompt has a dedicated priority rule for this alert type — if `attack_type` contains "Admin Account Creation" or MITRE technique contains T1136, the model skips all enrichment tools and immediately classifies as High/Critical with `likelihood ≥ 75` and `impact_score ≥ 80`. No AbuseIPDB or VirusTotal calls are made.

---

## Alert 2 — Failed Login / Brute Force Simulation

**MITRE ATT&CK:** T1110 (Brute Force)  
**Log Sources:** `WinEventLog:Security`  
**Event IDs:** 4625 (An account failed to log on)

**Detection Logic:**  
Aggregates failed login events (EID 4625) by computer, user, and source IP. Triggers when the count reaches 3 or more within the alert's time window.

```spl
index="chris-project" EventCode=4625
| eval user=coalesce(user, Account_Name, TargetUserName)
| eval src_ip=coalesce(src_ip, Source_Network_Address, IpAddress)
| stats count min(_time) as _time by ComputerName user src_ip
| where count >= 3
| table _time ComputerName user src_ip count
```

**Key fields passed to n8n:**
- `src_ip` — source of the brute force attempts (used for AbuseIPDB enrichment)
- `user` — the account being targeted
- `count` — number of failed attempts
- `ComputerName` — target machine

**LLM behaviour:**  
The system prompt IP enrichment logic checks whether `src_ip` is public or private. For the brute force scenario, a known-malicious public IP was manually substituted into the payload (since all VMs use private RFC1918 addresses). When a public IP is detected, the model calls AbuseIPDB-Enrichment and (if enabled) VirusTotal-Enrichment before producing its final output.

---

## Alert 3 — Hash Detection (Malicious File Execution)

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter), T1204 (User Execution)  
**Log Sources:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`  
**Event IDs:** Sysmon EID 1 (Process Creation)

**Detection Logic:**  
Captures all Sysmon process creation events and extracts the SHA256 hash via regex. Returns the most recent matching event. The hash is then passed to the LLM for VirusTotal lookup.

```spl
index=chris-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| rex field=Hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| eval alert_type="Malicious File Detection"
| table _time Computer Image CommandLine sha256
| head 1
```

**Key fields passed to n8n:**
- `sha256` — file hash (triggers VirusTotal-FileHash-Enrichment in the LLM)
- `Image` — the executable path
- `CommandLine` — full command including arguments
- `Computer` — host where execution occurred

**LLM behaviour:**  
The system prompt file hash enrichment logic detects `sha256` in the payload and calls VirusTotal-FileHash-Enrichment. The verdict is determined by the `malicious` count from VirusTotal's `last_analysis_stats`. Two sub-scenarios were tested: a clean hash (`splunk-admon.exe`, 0 detections → LOW) and DarkComet malware (67/72 detections → CRITICAL with isolation guidance).

---

## Alert 4 — Network Scanning / Reconnaissance

**MITRE ATT&CK:** T1046 (Network Service Discovery)  
**Log Sources:** `windows_firewall` (Windows Firewall logs)  
**Detection:** DROP events targeting Windows service ports

**Detection Logic:**  
Parses Windows Firewall DROP events using regex to extract source IP, destination IP, and ports. Filters for connections targeting common Windows service ports (135, 139, 445, 3389, 5985, 5986). Triggers when a source IP hits 3 or more unique ports, or generates 5 or more drops.

```spl
index=chris-project sourcetype=windows_firewall "DROP"
| rex field=_raw "DROP\s+\w+\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<src_port>\d+)\s+(?<dst_port>\d+)"
| where isnotnull(src_ip) AND isnotnull(dst_ip) AND isnotnull(dst_port)
| search dst_port IN (135,139,445,3389,5985,5986)
| stats count as drops
        dc(dst_port) as unique_ports
        values(dst_port) as ports
        latest(_time) as Raw_Splunk_time
        by src_ip dst_ip
| where unique_ports >= 3 OR drops >= 5
| eval attack_type="Network Scanning / Reconnaissance"
| eval mitre_technique="T1046"
| eval Raw_Splunk_time=strftime(Raw_Splunk_time,"%Y-%m-%d %H:%M:%S")
| table Raw_Splunk_time attack_type mitre_technique src_ip dst_ip ports unique_ports drops
```

**Key fields passed to n8n:**
- `src_ip` — scanning source (used for AbuseIPDB enrichment)
- `dst_ip` — target machine
- `ports` — list of ports targeted
- `drops` — total number of dropped connections
- `unique_ports` — number of distinct ports targeted

**LLM behaviour:**  
Same IP enrichment path as brute force — `src_ip` is checked, enrichment tools called if public. The `ports` and `drops` fields provide the model with enough context to classify scanning behaviour and recommend firewall block actions.

---

## Alert 5 — Suspicious PowerShell Execution

**MITRE ATT&CK:** T1059.001 (PowerShell)  
**Log Sources:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`  
**Event IDs:** Sysmon EID 1 (Process Creation)

**Detection Logic:**  
Filters Sysmon process creation events for PowerShell or pwsh processes (excluding Splunk's own PowerShell process). Applies regex pattern matching against the command line to detect known obfuscation and evasion flags. Only triggers if at least one suspicious flag is detected.

**Detected flags:**
- `EncodedCommand` — `-enc` or `-EncodedCommand`
- `IEX` — `Invoke-Expression`
- `Download` — `DownloadString`, `WebClient`, `Invoke-WebRequest`, `wget`, `curl`
- `NoProfile` — `-noprofile`
- `HiddenWindow` — `-WindowStyle Hidden`
- `ExecBypass` — `-ExecutionPolicy Bypass`
- `Base64Decode` — `FromBase64String`

```spl
index="chris-project" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventID=1)
| eval image_lc=lower(coalesce(Image,"")), cmd_lc=lower(coalesce(CommandLine,""))
| where like(image_lc,"%\\powershell.exe") OR like(image_lc,"%\\pwsh.exe")
| where NOT like(image_lc,"%\\splunk-powershell.exe")
| eval flags=mvappend(
    if(match(cmd_lc,"(^|\\s)-enc(odedcommand)?(\\s|$)"),"EncodedCommand",null()),
    if(match(cmd_lc,"\\biex\\b|invoke-expression"),"IEX",null()),
    if(match(cmd_lc,"downloadstring\\(|new-object\\s+net\\.webclient|invoke-webrequest\\b|(^|\\s)iwr(\\s|$)|(^|\\s)wget(\\s|$)|(^|\\s)curl(\\s|$)"),"Download",null()),
    if(match(cmd_lc,"(^|\\s)-nop(rofile)?(\\s|$)"),"NoProfile",null()),
    if(match(cmd_lc,"(^|\\s)-w\\s+hidden(\\s|$)|(^|\\s)-windowstyle\\s+hidden(\\s|$)"),"HiddenWindow",null()),
    if(match(cmd_lc,"(^|\\s)-exec\\s+bypass(\\s|$)|(^|\\s)-executionpolicy\\s+bypass(\\s|$)"),"ExecBypass",null()),
    if(match(cmd_lc,"frombase64string\\("),"Base64Decode",null())
  )
| eval flags=mvfilter(isnotnull(flags))
| where mvcount(flags) > 0
| eval attack_type="Suspicious PowerShell Execution"
| eval mitre_technique="T1059.001"
| stats latest(_time) as Raw_Splunk_time
        values(User) as User
        values(host) as host
        values(Computer) as Computer
        values(Image) as Image
        values(CommandLine) as CommandLine
        values(ParentImage) as ParentImage
        values(ParentCommandLine) as ParentCommandLine
        values(Hashes) as Hashes
        values(flags) as flags
        count as hits
  by attack_type mitre_technique
| eval Raw_Splunk_time=strftime(Raw_Splunk_time,"%Y-%m-%d %H:%M:%S")
| table Raw_Splunk_time attack_type mitre_technique User host Computer Image CommandLine ParentImage ParentCommandLine Hashes flags hits
```

**Key fields passed to n8n:**
- `CommandLine` — full command (LLM uses this to describe what the PowerShell was doing)
- `flags` — list of detected evasion techniques
- `ParentImage` / `ParentCommandLine` — parent process context
- `Image` — full path to powershell.exe
- `hits` — number of matching events

**LLM behaviour:**  
No enrichment tools are called for this alert type — no external IP or file hash is present. The model relies entirely on the command line content and flags to classify severity and generate recommendations. This tests the LLM's ability to reason about obfuscated commands from log data alone.

---

## Summary Table

| Alert | MITRE | Event Source | Key Field | Enrichment |
|---|---|---|---|---|
| Admin Account Creation | T1136, T1078 | WinEventLog:Security | target_account | None (priority rule) |
| Brute Force | T1110 | WinEventLog:Security | src_ip | AbuseIPDB + VirusTotal |
| Hash Detection | T1059, T1204 | Sysmon EID 1 | sha256 | VirusTotal (file hash) |
| Network Scanning | T1046 | Windows Firewall | src_ip | AbuseIPDB + VirusTotal |
| PowerShell | T1059.001 | Sysmon EID 1 | CommandLine + flags | None |
