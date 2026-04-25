# Prompts and Code Reference

This document contains the full text of all prompts and custom code used in the LARA pipeline. Anyone importing the n8n workflow JSON will have these embedded automatically, but this file provides a readable reference for understanding what each component does and why.

---

## Workflow Overview

The pipeline uses a single n8n workflow for all alert types. Pipeline B (LLM-Only) was not a separate workflow — it was achieved by disabling the AbuseIPDB-Enrichment, VirusTotal-Enrichment, and VirusTotal-FileHash-Enrichment tool nodes. Pipeline A (Manual) had no automation at all.

The workflow canvas:

![Workflow Canvas](../screenshots/workflow-canvas.png)

**Node flow:**
```
Webhook (5 types) → Set Link → GPT-4.1 Mini (with tools) → Code in JavaScript → DFIR-IRIS HTTP Request → DFIR-IRIS HTTP Request1 → If (severity check) → Send a message (Slack)
```

The three enrichment tools (AbuseIPDB-Enrichment, VirusTotal-Enrichment, VirusTotal-FileHash-Enrichment) are called by the LLM mid-execution when the system prompt logic determines they are needed — not as separate linear nodes.

---

## 1. GPT-4.1 Mini — System Prompt

The system prompt defines the model's role, output schema, tool usage rules, and risk scoring logic. It is strict and schema-enforced — the model is instructed to return only a single valid JSON object with no surrounding text.

```
You are a cybersecurity SOC analysis assistant operating in a tool-enabled SOC automation environment.

Your task:
Analyse incoming Splunk alerts and return exactly ONE valid JSON object that strictly matches the required schema.

STRICT OUTPUT RULES:
- Output ONLY a single valid JSON object.
- No text, no explanations, no markdown.
- Follow the schema EXACTLY.
- Do not add or remove fields.
- If data is missing, use null, empty string, empty array, or 0.
- Never fabricate enrichment results.
- Never guess threat intelligence.
- Do not output tool responses directly.

=====================================================================
TOOL USAGE RULES (MANDATORY)
=====================================================================

Enrichment must occur BEFORE final JSON output when required.

-----------------------------------------------------
1️⃣ ADMIN ACCOUNT CREATION PRIORITY RULE
-----------------------------------------------------

If:
- attack_type contains "Admin Account Creation"
OR
- mitre_technique contains "T1136"

Then:
- Classify as Persistence and Privilege Escalation.
- Default severity MUST be "High" minimum.
- likelihood MUST be ≥ 75.
- impact_score MUST be ≥ 80.
- Do NOT call VirusTotal.
- Do NOT call AbuseIPDB.
- Skip all enrichment.
- Immediately proceed to structured output.

-----------------------------------------------------
2️⃣ IP ENRICHMENT LOGIC
-----------------------------------------------------

If body.result.src_ip exists:

If IP is private (RFC1918 ranges):
- Do NOT call enrichment tools.
- IOC verdict:
  "Internal IP address (RFC1918), no external threat intelligence applicable."
- vt_link = null
- abuseipdb_link = null

If IP is public:
- Call AbuseIPDB-Enrichment (mandatory).
- Call VirusTotal-Enrichment only if enabled.
- Wait for tool responses before final output.
- Use results to adjust likelihood and IOC verdict.

IOC links:
abuseipdb_link: https://www.abuseipdb.com/check/<IP>
vt_link: https://www.virustotal.com/gui/ip-address/<IP>

-----------------------------------------------------
3️⃣ FILE HASH ENRICHMENT LOGIC
-----------------------------------------------------

If body.result.sha256 exists:

- Call VirusTotal-FileHash-Enrichment
- Tool input format EXACTLY:
  {"sha256": "<SHA256 value>"}

Wait for tool response before final output.

Use:
data.attributes.last_analysis_stats.malicious
data.attributes.last_analysis_stats.suspicious
data.attributes.last_analysis_stats.harmless
data.attributes.last_analysis_stats.undetected

Verdict rules:
- malicious > 0 → "Malicious file detected by VirusTotal engines."
- suspicious > 0 and malicious = 0 → "Suspicious file flagged by some engines."
- malicious = 0 and suspicious = 0 → "No malicious detections on VirusTotal."
- No VT data → "No VirusTotal data available; requires manual review."

vt_link:
https://www.virustotal.com/gui/file/<SHA256>

abuseipdb_link must be null for file hashes.

=====================================================================
RISK SCORING LOGIC (MANDATORY)
=====================================================================

Output:
- impact_score (0–100)
- likelihood (0–100)
- risk_score = round((impact_score + likelihood) / 2)

Severity mapping:

risk < 40 → "Low"
40 ≤ risk < 70 → "Medium"
70 ≤ risk < 90 → "High"
risk ≥ 90 → "Critical"

Be conservative.

Never assign High or Critical to:
- Single internal brute-force attempts
- Obvious benign testing
- Policy violations without compromise evidence

=====================================================================
IMPACT SCALE
=====================================================================

0–30: Minimal impact (test systems, internal IP, non-privileged users)
31–60: Workstations, normal users
61–80: Servers, privileged accounts
81–100: Domain admin, production, sensitive data

=====================================================================
LIKELIHOOD SCALE
=====================================================================

0–30: Likely benign
31–60: Possibly malicious
61–80: Likely malicious pattern
81–100: Strong evidence of compromise

=====================================================================
TIME HANDLING RULE
=====================================================================

- raw_time MUST equal Raw_Splunk_time exactly.
- Do NOT modify format.
- Do NOT convert.
- Do NOT invent timestamps.
- Only use Raw_Splunk_time.

=====================================================================
IOC RULES (MANDATORY)
=====================================================================

- Always include an IOC for the host (type: "host").

- If target_account exists:
  Add an IOC:
  type: "user"
  value: target_account
  verdict: "Account that was created or modified with administrative privileges."
  vt_link: null
  abuseipdb_link: null

- If initiating_user exists AND initiating_user is different from target_account:
  Add an additional IOC:
  type: "user"
  value: initiating_user
  verdict: "Account that performed the administrative change."
  vt_link: null
  abuseipdb_link: null

=====================================================================
MITRE MAPPING RULES
=====================================================================

- Include 0–2 best mappings.
- If unclear → use empty array [].
- Each mapping must include:
  tactic
  technique_id
  technique_name

=====================================================================
SCHEMA (DO NOT CHANGE)
=====================================================================

{
  "alert_type": "",
  "title": "",
  "severity": "",
  "raw_time": "",
  "risk_score": 0,
  "likelihood": 0,
  "impact_score": 0,
  "summary": "",

  "mitre_attack": [
    {
      "tactic": "",
      "technique_id": "",
      "technique_name": ""
    }
  ],

  "iocs": [
    {
      "type": "",
      "value": "",
      "verdict": "",
      "vt_link": null,
      "abuseipdb_link": null
    }
  ],

  "recommended_actions": [
    ""
  ],

  "links": {
    "splunk": null,
    "ticket": null
  }
}
```

---

## 2. GPT-4.1 Mini — User Prompt

The user prompt is a dynamic template in n8n. It populates with live data from the incoming Splunk webhook payload at runtime. Fields that are not present in a given alert type are passed as empty/null.

```
Alert: {{ $json.body.search_name }}
Alert Detail: {{ JSON.stringify($json.body.result, null, 2) }}
Raw_Splunk_time: {{ $json.body.result._time }}
Source IP: {{ $json.body.result.src_ip }}
Destination IP: {{ $json.body.result.dst_ip }}
Dropped Attempts: {{ $json.body.result.drops }}
Targeted Ports: {{ $json.body.result.ports }}
```

**Why this structure:**
The user prompt deliberately passes the full `result` object as raw JSON (`JSON.stringify`) alongside individually extracted fields. This gives the model both structured field access and full context — important because different alert types have different field names in Splunk (e.g. brute force alerts have `src_ip`, file hash alerts have `sha256`, privilege escalation alerts have `target_account`).

---

## 3. Code in JavaScript Node

This is the largest and most complex node in the workflow. It runs after GPT-4.1 Mini returns its JSON analysis and is responsible for:

- Parsing the LLM JSON output
- Converting and normalising timestamps
- Calculating the final risk level for display
- Building the full Slack message (formatted with IOC tables, recommended actions, links)
- Building the DFIR-IRIS alert payload (`/alerts/add`)
- Building the DFIR-IRIS escalation payload (`/alerts/escalate/{id}`)
- Generating structured tags for IRIS (severity, detection type, MITRE techniques, IOC types)
- Determining the correct IRIS classification ID based on alert type
- Routing Slack output to the correct severity channel (#soc-low, #soc-med, #soc-high, #soc-critical)

```javascript
// ============================================================
// n8n JavaScript node — Slack formatting + DFIR-IRIS payloads
// Tagging refined for ALL alerts (det-*, sev-*, tactic-*, mitre-*, source-*, automation-*)
// ============================================================

// -----------------------------
// 0) CONFIG
// -----------------------------
const IRIS_CUSTOMER_ID = 1;
const IRIS_ALERT_SOURCE = "Splunk+n8n";
const IRIS_DEFAULT_CLASSIFICATION_ID = 36; // other:other

// Risk -> IRIS severity IDs
const IRIS_ALERT_SEVERITY = {
  Low: 2,
  Medium: 4,
  High: 5,
  Critical: 6,
};

// Classification IDs (matched to your IRIS instance)
const CLASS_IDS = {
  OTHER: 36,
  PORT_SCAN: 11,
  RDP_BRUTEFORCE: 15,
  ADMIN_ACCOUNT: 17,
  POWERSHELL: 21,
  FILE_HASH: 7,
};

// -----------------------------
// Helper functions
// -----------------------------
function slugify(s) {
  return String(s || "")
    .trim()
    .toLowerCase()
    .replace(/['"]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function uniqAdd(set, v) {
  if (!v) return;
  const t = String(v).trim();
  if (t) set.add(t);
}

// Detect a stable detection tag across all alert types using title/alert_type text
function detectDetTag(titleKey, typeKey) {
  const t = `${titleKey} ${typeKey}`;

  if (t.includes("port") && t.includes("scan")) return "det-port-scan";
  if (t.includes("rdp") && (t.includes("brute") || t.includes("force") || t.includes("login"))) return "det-rdp-bruteforce";
  if ((t.includes("admin") && t.includes("account")) || t.includes("account creation") || t.includes("create account")) return "det-admin-account-creation";
  if (t.includes("powershell")) return "det-suspicious-powershell";
  if (t.includes("hash") || t.includes("sha") || (t.includes("file") && t.includes("malware"))) return "det-file-hash";
  return "det-other";
}

// Map det-tag -> IRIS classification id
function classificationFromDet(detTag) {
  switch (detTag) {
    case "det-port-scan": return CLASS_IDS.PORT_SCAN;
    case "det-rdp-bruteforce": return CLASS_IDS.RDP_BRUTEFORCE;
    case "det-admin-account-creation": return CLASS_IDS.ADMIN_ACCOUNT;
    case "det-suspicious-powershell": return CLASS_IDS.POWERSHELL;
    case "det-file-hash": return CLASS_IDS.FILE_HASH;
    default: return CLASS_IDS.OTHER;
  }
}

// -----------------------------
// 1) Parse AI JSON from GPT node
// -----------------------------
let raw = "{}";

if (
  $json.output &&
  Array.isArray($json.output) &&
  $json.output[0] &&
  Array.isArray($json.output[0].content) &&
  $json.output[0].content[0] &&
  $json.output[0].content[0].text
) {
  raw = $json.output[0].content[0].text;
}

let data;
try {
  data = JSON.parse(raw);
} catch (e) {
  data = {};
}

// -----------------------------
// 2) Convert raw_time safely
// -----------------------------
let alertTime = "Unknown";
let sourceEventTime = null;

if (data.raw_time !== undefined && data.raw_time !== null && data.raw_time !== "") {
  const rawTimeStr = String(data.raw_time).trim();

  if (rawTimeStr.toLowerCase() !== "null" && rawTimeStr.toLowerCase() !== "undefined") {
    const ts = parseFloat(rawTimeStr);

    if (!Number.isNaN(ts) && Number.isFinite(ts)) {
      const d = new Date(ts * 1000);
      if (!Number.isNaN(d.getTime())) {
        sourceEventTime = d.toISOString();
      }
    } else {
      const parsedDate = new Date(rawTimeStr);
      if (!Number.isNaN(parsedDate.getTime())) {
        sourceEventTime = parsedDate.toISOString();
      }
    }
  }
}

// Fallback: try Splunk event time
if (!sourceEventTime) {
  const splunkTime =
    $json.body?.result?._time ||
    $json.body?.result?.time ||
    $json.body?._time ||
    null;

  if (splunkTime) {
    const splunkTimeStr = String(splunkTime).trim();
    const ts = parseFloat(splunkTimeStr);

    if (!Number.isNaN(ts) && Number.isFinite(ts)) {
      const d = new Date(ts * 1000);
      if (!Number.isNaN(d.getTime())) {
        sourceEventTime = d.toISOString();
      }
    } else {
      const parsedDate = new Date(splunkTimeStr);
      if (!Number.isNaN(parsedDate.getTime())) {
        sourceEventTime = parsedDate.toISOString();
      }
    }
  }
}

// Final fallback: current time
if (!sourceEventTime) {
  sourceEventTime = new Date().toISOString();
}

const displayDate = new Date(sourceEventTime);
if (!Number.isNaN(displayDate.getTime())) {
  alertTime = displayDate.toLocaleString("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Europe/London",
  });
}

// -----------------------------
// 3) Risk level
// -----------------------------
const impact10 = Math.round(((data.impact_score ?? data.risk_score) || 0) / 10);
const like10   = Math.round((data.likelihood || 0) / 10);

let riskIndex = Math.round((impact10 + like10) / 2);
if (!Number.isFinite(riskIndex)) riskIndex = 0;
riskIndex = Math.max(0, Math.min(10, riskIndex));

let riskLevel = "Low";
if (riskIndex >= 4) riskLevel = "Medium";
if (riskIndex >= 7) riskLevel = "High";
if (riskIndex >= 9) riskLevel = "Critical";

// -----------------------------
// 4) Slack emoji + channel routing
// -----------------------------
let emoji = "⚪";
if (riskLevel === "Low") emoji = "🟢";
if (riskLevel === "Medium") emoji = "🟡";
if (riskLevel === "High") emoji = "🟠";
if (riskLevel === "Critical") emoji = "🔴";

let detailsChannel = "#soc-low";
if (riskLevel === "Medium") detailsChannel = "#soc-med";
if (riskLevel === "High") detailsChannel = "#soc-high";
if (riskLevel === "Critical") detailsChannel = "#soc-critical";

// -----------------------------
// 5) IOC table + best IOC
// -----------------------------
let iocTable = "```Type    Value                         Verdict\n";
iocTable += "-------------------------------------------------------------------------------\n";

const iocs = Array.isArray(data.iocs) ? data.iocs : [];

const bestIoc =
  iocs.find(i => i.type === "ip")?.value ||
  iocs.find(i => i.type === "host")?.value ||
  iocs.find(i => i.type === "user")?.value ||
  iocs.find(i => String(i.type || "").toLowerCase().includes("hash"))?.value ||
  "No IOC";

for (const ioc of iocs) {
  const vt = ioc.vt_link ? `<${ioc.vt_link}|VT>` : "-";
  const ab = ioc.abuseipdb_link ? `<${ioc.abuseipdb_link}|AIPDB>` : "-";
  iocTable += `${(ioc.type || "").padEnd(7)} ${(ioc.value || "").padEnd(30)} ${(ioc.verdict || "").padEnd(12)} ${vt}/${ab}\n`;
}
iocTable += "```";

// -----------------------------
// 6) Recommended actions
// -----------------------------
let actions = "";
for (const a of (data.recommended_actions || [])) {
  actions += `• ${a}\n`;
}

// -----------------------------
// 7) Splunk link
// -----------------------------
const host = $json.body?.result?.host || $json.body?.result?.computer || "";
const sourcetype =
  $json.body?.result?.sourcetype ||
  $json.sourcetype ||
  "XmlWinEventLog";

let splunkQuery = `search index=*`;
if (host) splunkQuery += ` host="${host}"`;
if (sourcetype) splunkQuery += ` sourcetype="${sourcetype}"`;

const splunkLink =
  `http://192.168.106.129:8000/en-US/app/search/search?q=${encodeURIComponent(splunkQuery)}&earliest=-24h&latest=now`;

// -----------------------------
// 8) Slack message
// -----------------------------
let fullMessage = `
*${emoji} ${data.title || "SOC Alert"}*

*Type:* \`${data.alert_type || ""}\`
*Severity:* \`[ ${riskLevel.toUpperCase()} ]\`
*Time Detected:* ${alertTime}

*Summary*
${"```"}${data.summary || ""}${"```"}

*Indicators*
${iocTable}

*Recommended Actions*
${actions}

*Links*
• Splunk: ${splunkLink ? `<${splunkLink}|Open>` : "N/A"} | IRIS Case: (see below)

`;

let summaryMessage = `${emoji} *${data.title || "SOC Alert"}* — ${data.alert_type || ""} | Severity: ${riskLevel}`;

// ============================================================
// 9) TAGGING
// ============================================================

const rawTitle = String(data.title || "");
const rawType  = String(data.alert_type || "");
const titleKey = rawTitle.trim().toLowerCase();
const typeKey  = rawType.trim().toLowerCase();

const detTag = detectDetTag(titleKey, typeKey);

const mitre = Array.isArray(data.mitre_attack) ? data.mitre_attack : [];

const tagSet = new Set();

uniqAdd(tagSet, `sev-${riskLevel.toLowerCase()}`);
uniqAdd(tagSet, detTag);
uniqAdd(tagSet, "source-splunk");
uniqAdd(tagSet, "automation-ai");
uniqAdd(tagSet, "pipeline-n8n");

for (const m of mitre) {
  if (m?.tactic) uniqAdd(tagSet, `tactic-${slugify(m.tactic)}`);
  if (m?.technique_id) uniqAdd(tagSet, `mitre-${String(m.technique_id).toUpperCase()}`);
}

if (mitre.length === 0 && rawType) {
  uniqAdd(tagSet, `theme-${slugify(rawType)}`);
}

for (const ioc of iocs) {
  if (!ioc?.type) continue;
  uniqAdd(tagSet, `ioc-${slugify(ioc.type)}`);
}

const irisTags = Array.from(tagSet).join(",");

// ============================================================
// 10) CLASSIFICATION
// ============================================================

let classificationId = Number.isInteger(data.iris_classification_id)
  ? data.iris_classification_id
  : classificationFromDet(detTag);

if (!Number.isInteger(classificationId)) classificationId = IRIS_DEFAULT_CLASSIFICATION_ID;

// ============================================================
// 11) Severity + status
// ============================================================

const alertSeverityId = IRIS_ALERT_SEVERITY[riskLevel] ?? IRIS_ALERT_SEVERITY.Medium;
const alertStatusId = 1;

// -----------------------------
// 12) IRIS alert body
// -----------------------------
const irisAlertBody = {
  alert_title: `[${riskLevel}] ${rawType || "SOC Alert"} - ${bestIoc}`,
  alert_description: data.summary || (data.title || "SOC Alert"),
  alert_source: IRIS_ALERT_SOURCE,
  alert_source_ref: $json.body?.sid || data.links?.ticket || `splunk:${host || "unknown-host"}`,
  alert_source_link: splunkLink,
  alert_customer_id: IRIS_CUSTOMER_ID,
  alert_severity_id: alertSeverityId,
  alert_status_id: alertStatusId,
  alert_classification_id: classificationId,
  alert_tags: irisTags,
  alert_source_event_time: sourceEventTime,
  alert_note: fullMessage,
  alert_source_content: {
    splunk: $json.body || null,
    ai_report: data || null,
  },
  alert_iocs: [],
  alert_assets: [],
};

// -----------------------------
// 13) Escalation body
// -----------------------------
const irisEscalateBody = {
  iocs_import_list: [],
  assets_import_list: [],
  note: `Escalated automatically from Splunk+n8n. Best IOC: ${bestIoc}.`,
  import_as_event: true,
  case_tags: irisTags,
};

// -----------------------------
// 14) Return
// -----------------------------
return {
  slackMessage: fullMessage,
  summaryMessage,
  detailsChannel,
  irisAlertBody,
  irisEscalateBody,
  debug_title: rawTitle,
  debug_alert_type: rawType,
  debug_detTag: detTag,
  debug_classificationId: classificationId,
  debug_tags: irisTags,
  debug_raw_time: data.raw_time,
  debug_sourceEventTime: sourceEventTime,
  riskLevel,
  alertTime,
  parsedReport: data,
};
```

---

## 4. Design Decisions

**Why a strict JSON schema in the system prompt?**
Without schema enforcement, LLMs produce inconsistent output structures — sometimes adding explanatory text, sometimes changing field names. The JavaScript node expects exact field names (`data.iocs`, `data.mitre_attack`, etc.). Any deviation causes silent failures downstream. The strict schema eliminates this.

**Why does the system prompt handle tool calling logic?**
GPT-4.1 Mini supports tool calling natively, but it needs explicit instructions about *when* to call tools and *what to do with the results*. Without the enrichment logic in the system prompt, the model would call tools inconsistently — sometimes querying AbuseIPDB for internal IPs (which would waste API calls and return no useful data), sometimes skipping enrichment for public IPs.

**Why two DFIR-IRIS HTTP request nodes?**
The first node creates the alert (`POST /alerts/add`) and returns an alert ID. The second node escalates it to a full investigation case (`POST /alerts/escalate/{id}`) using that ID. These must be sequential — escalation requires the alert to exist first.

**Why the If node before Slack?**
Slack notifications are sent only for High and Critical severity alerts. Low and Medium severity alerts are still created in DFIR-IRIS (full audit trail) but do not generate a Slack notification — preventing alert fatigue for lower-priority events.
