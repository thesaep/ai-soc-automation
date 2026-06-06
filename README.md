# AI-Powered SOC Automation Platform
A modular SOC automation platform built with Splunk, Python, and Claude AI. Detects threats mapped to MITRE ATT&CK, analyzes them with an AI SOC analyst, and triggers automated incident response — end to end.
Built in public as a detection-engineering portfolio project. Each phase is documented on Medium.

Phase 1 detected brute force only. Phase 2 added index-time log normalization and a 12-rule MITRE ATT&CK detection engine, validated in a dedicated attack-simulation lab.

## Architecture
Windows VM (Log Source: Security/System/Application + Sysmon)
        ↓ Universal Forwarder
Ubuntu VM (Splunk Enterprise — index-time field normalization)
        ↓ REST API
Python (12 MITRE ATT&CK detections + event normalization)
        ↓ Claude API
AI Analysis (per-technique MITRE context injection) + SOAR Playbook
        ↓
Email Notification + Incident Log

## Features

**MITRE ATT&CK Detection Engine** — 12 detections across 6 tactics, converted from Sigma rules to SPL
**Brute Force Detection** — advanced detection rules with custom SPL (Phase 1)
**Risk Scoring** — CRITICAL / HIGH / MEDIUM / LOW severity levels
**Index-Time Log Normalization** — field extraction handled in Splunk props.conf (no per-query rename)
**AI Analysis** — Claude evaluates each event with injected MITRE context and connects related events into attack chains
**Automated Alert Management** — create_alerts.py creates/updates all Splunk alerts via REST API (idempotent upsert)
**Automated Email Alerts** — for high-severity incidents
**Incident Logging** — persistent JSON-based audit trail
**Multi-Value Field Handling** — localization-aware (supports non-English Windows logs)
**Machine Account Filtering** — reduces false positives
**Attack-Simulation Lab** — detections validated with Atomic Red Team + Sysmon telemetry

MITRE ATT&CK Coverage
TacticTechniqueSeverityValidationDefense EvasionT1070.001 — Clear Event Logs🔴 CRITICAL✅ LabLateral MovementT1550.002 — Pass-the-Hash🔴 CRITICAL✅ LabPersistenceT1053.005 — Scheduled Task🟠 HIGH✅ LabExecutionT1059 — Obfuscation via MSHTA🟠 HIGHPatternExecutionT1059 — Obfuscation via Rundll32🟠 HIGHPatternExecutionT1059 — Obfuscation via Stdin🟠 HIGHPatternInitial AccessT1078 — External RDP Login🟠 HIGHPatternInitial AccessT1078 — External SMB Login🟠 HIGHPatternInitial AccessT1078 — Suspicious Failed Logon Reasons🟡 MEDIUMPatternInitial AccessT1078 — Suspicious Failed Logon Source🟡 MEDIUMPatternDiscoveryT1069 — LDAP Recon🟡 MEDIUMRequires DCDiscoveryT1082 — Network Recon🟡 MEDIUMRequires DC

✅ Lab = fired end-to-end against real telemetry.
Pattern = production-grade rule, validated against known attack patterns.
Requires DC = needs a Domain Controller to generate the relevant events.

Tech Stack
ComponentTechnologySIEMSplunk Enterprise 9.3BackendPython 3.10AIClaude Sonnet 4.6 (Anthropic)Detection RulesSigma → SPL (sigma-cli)Attack SimulationAtomic Red Team + Sysmon (SwiftOnSecurity config)Server OSUbuntu Server 22.04Endpoint OSWindows 10/11Log ForwarderSplunk Universal Forwarder

Screenshots




## Tech Stack

| Component | Technology |
|-----------|------------|
| SIEM | Splunk Enterprise 9.3 |
| Backend | Python 3.10 |
| AI | Claude Sonnet 4.6 (Anthropic) |
| Server OS | Ubuntu Server 22.04 |
| Endpoint OS | Windows 10/11 |
| Log Forwarder | Splunk Universal Forwarder |

## Screenshots

### Splunk Dashboard — Brute Force Detection
![Dashboard](screenshots/Dashboard.png)

Main dashboard showing brute force activity across all risk levels. CRITICAL and HIGH severity events appear at the top.

### Alert Rule
![Alert](screenshots/Alerts.png)

Automated alert running every 5 minutes, capturing CRITICAL and HIGH severity events.

### Python SOAR Playbook — CRITICAL Event Analysis
![SOAR Critical](screenshots/soar_playbook_1.png)

Claude AI analyzing a CRITICAL severity event and triggering the email notification flow.

### Python SOAR Playbook — HIGH Event Analysis
![SOAR High](screenshots/soar_playbook_2.png)
![SOAR High 2](screenshots/soar_playbook_3.png)

Analysis of HIGH severity brute force events with 35 and 25 failed login attempts.

### Python SOAR Playbook — LOW Event Analysis
![SOAR Low](screenshots/soar_playbook_4.png)
![SOAR Low 2](screenshots/soar_playbook_5.png)
![SOAR Low 3](screenshots/soar_playbook_6.png)

Low-severity events are logged only — no email is sent. AI evaluates the likelihood of false positives.

### Email Notification
![Email 1](screenshots/mail_bildirimi_1.png)
![Email 2](screenshots/mail_bildirimi_2.png)
![Email 3](screenshots/mail_bildirimi_3.png)

Detailed automated email notifications sent for CRITICAL and HIGH severity events. AI analysis is included in the email body.

### Incident Log File
![JSON 1](screenshots/json_1.png)
![JSON 2](screenshots/json_2.png)

All detected events are stored with timestamps in `logs/incidents.json`. AI analysis is also included in the log.

## Risk Scoring Logic

| Risk | Condition | Action |
|------|-----------|--------|
| CRITICAL | 20+ failures + 1+ success | Email + Log + AI Analysis |
| HIGH | 20+ failures | Email + Log + AI Analysis |
| HIGH | 10-20 failures + success | Email + Log + AI Analysis |
| MEDIUM | 10-20 failures | Log + AI Analysis |
| MEDIUM | 5-10 failures + success | Log + AI Analysis |
| LOW | 5-10 failures | Log + AI Analysis |

## Installation

1. Copy `.env.example` to `.env`
2. Fill in the required values (Splunk credentials, Anthropic API key, Email)
3. Install dependencies:
```bash
   pip3 install -r requirements.txt
```
4. Run:
```bash
   python3 soar_playbook.py
```

## File Structure
ai-soc-automation/
├── README.md
├── .env                       # Secrets (gitignored)
├── .gitignore
├── requirements.txt
├── splunk_connector.py        # Splunk API connector
├── ai_analyzer.py             # Claude AI threat analyzer
├── soar_playbook.py           # SOAR playbook (email + log)
├── queries/
│   └── brute_force.spl        # SPL query (externalized)
├── logs/
│   └── incidents.json         # Incident log file
└── screenshots/               # Project screenshots


## License

MIT
