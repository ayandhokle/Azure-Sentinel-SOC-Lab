# 🛡️ AI-Assisted Threat Detection & Triage using Microsoft Sentinel

![Azure](https://img.shields.io/badge/Azure-Microsoft%20Sentinel-0078D4?style=flat&logo=microsoftazure)
![KQL](https://img.shields.io/badge/Query-KQL-FF6F00?style=flat)
![SOAR](https://img.shields.io/badge/Automation-Logic%20Apps-0089D6?style=flat&logo=microsoftazure)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=flat)

A cloud-native SOC home lab built on **Microsoft Sentinel** to simulate real-world attack scenarios, detect threats using AI/ML-powered analytics, hunt threats with KQL, and automate incident response using Logic Apps (SOAR).

This lab bridges the gap between traditional on-prem SIEM tools (Wazuh, Splunk) and modern cloud-native AI-assisted SOC operations.

---

## 📌 Objectives

- Deploy and configure Microsoft Sentinel as a cloud-native SIEM
- Ingest Windows Security Event logs from an Azure VM
- Simulate attack techniques: RDP brute-force, persistence via scheduled tasks, suspicious PowerShell
- Detect threats using built-in ML Fusion rules and UEBA (User and Entity Behavior Analytics)
- Write custom KQL hunting queries for proactive threat detection
- Automate incident response notifications using Logic Apps playbook
- Use Microsoft Copilot for Security to summarize and triage incidents

---

## 🧰 Tools & Technologies

| Tool | Purpose |
|------|---------|
| Microsoft Sentinel | Cloud-native SIEM/SOAR |
| Azure Log Analytics Workspace | Log ingestion and storage |
| Azure Windows 10 VM | Target/victim machine |
| KQL (Kusto Query Language) | Threat hunting queries |
| Fusion ML Rules | AI-powered multi-signal correlation |
| UEBA | User and Entity Behavior Analytics |
| Logic Apps | SOAR playbook automation |
| Copilot for Security | AI-assisted incident triage |
| Kali Linux (local) | Attack simulation |

---

## 🔬 Lab Phases

### Phase 1 — Azure & Sentinel Setup
- Created Azure free account
- Deployed Windows 10 VM in Azure
- Created Log Analytics Workspace
- Connected Microsoft Sentinel to the workspace
- Enabled data connectors: Windows Security Events, Azure Activity

---

### Phase 2 — Attack Simulation

| Attack | Technique | Event ID |
|--------|-----------|----------|
| RDP Brute-force | Multiple failed login attempts | 4625 |
| Persistence | Scheduled task creation | 4698 |
| Suspicious PowerShell | Encoded command execution | 4104 |
| Privilege Escalation attempt | Local admin group enumeration | 4732 |

---

### Phase 3 — AI-Powered Detection

**Fusion ML Rule** — Correlated failed logins + scheduled task creation into a single High severity incident flagged as Credential Access → Persistence attack chain.

**UEBA** — Flagged anomalous login times and new scheduled tasks outside baseline behavior automatically.

**Custom KQL Hunting Queries** — 4 queries written. See `/kql-queries/`.


---

### Phase 4 — SOAR Automation & AI Triage

**Logic Apps Playbook** — Trigger: High severity incident → Action: Send email with incident details.

**Copilot for Security** — Used to generate natural language incident summary, identify affected entities, and suggest remediation steps.

---

## 📊 Key Findings

| Detection Method | Alert Generated | Severity |
|-----------------|----------------|----------|
| Custom KQL — RDP Brute-force | ✅ Yes | High |
| Custom KQL — Scheduled Task | ✅ Yes | Medium |
| Custom KQL — Encoded PowerShell | ✅ Yes | Medium |
| Fusion ML Rule | ✅ Yes — correlated brute-force + persistence | High |
| UEBA Anomaly | ✅ Yes — behavioral baseline deviation | Medium |

---

## 📝 KQL Queries Overview

### RDP Brute-force Detection
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(10m)
| summarize FailedAttempts = count() by IpAddress, Account, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5
| project TimeGenerated, IpAddress, Account, FailedAttempts
```

### Scheduled Task Creation
```kql
SecurityEvent
| where EventID == 4698
| project TimeGenerated, Account, Computer, EventData
| order by TimeGenerated desc
```

### Encoded PowerShell
```kql
SecurityEvent
| where EventID == 4104
| where ScriptBlockText contains "-enc" or ScriptBlockText contains "-EncodedCommand"
| project TimeGenerated, Computer, Account, ScriptBlockText
```

---

## 💡 Lessons Learned

- Fusion ML correlated two medium-severity alerts into one high-severity incident — a pattern static rules miss without complex correlation logic
- UEBA flagged anomalies without hardcoded thresholds
- KQL is more readable than SPL and closer to SQL
- Cloud SIEM scales automatically — no storage or indexing management
- Even a basic Logic Apps playbook meaningfully reduces MTTR

---

## 🔗 Related Projects

| Project | Description |
|---------|-------------|
| [Wazuh SOC Lab](https://github.com/ayandhokle/wazuh-soc-lab) | On-prem SIEM with custom detection rules, FIM, active response |
| [Splunk SOC Lab](https://github.com/ayandhokle/splunk-soc-lab) | Log analysis with 500+ events and SPL queries |
| [SSH Brute-Force Detection](https://github.com/ayandhokle/ssh-bruteforce-detection) | Hydra-based attack simulation with Splunk detection |
| [Malware Detection Lab](https://github.com/ayandhokle/malware-detection-lab) | EICAR test files, ClamAV, Splunk log ingestion |

---

## 👤 Author

**Ayan Dhokle**  
GitHub: [github.com/ayandhokle](https://github.com/ayandhokle)  
LinkedIn: [linkedin.com/in/ayandhokle](https://linkedin.com/in/ayandhokle)  
CompTIA Security+ (SY0-701) | CompTIA Network+

---

> ⚠️ **Disclaimer:** This lab is built purely for educational purposes in a controlled environment. All attack simulations were performed on personal infrastructure.
