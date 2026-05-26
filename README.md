# AI-Powered SOC Automation Platform

A modular SOC automation platform built with Splunk, Python, and Claude AI. Automatically detects brute force attacks(for now, it's just brute force; the scope will be expanded further in the future), analyzes them with AI, and triggers email notifications.

## Architecture

Windows Host (Log Source)
↓ Universal Forwarder
Ubuntu VM (Splunk Enterprise)
↓ REST API
Python (Anomaly Detection)
↓ Claude API
AI Analysis + SOAR Playbook
↓
Email Notification + Incident Log

## Features

- **Brute Force Detection** — Advanced detection rules with custom SPL
- **Risk Scoring** — CRITICAL / HIGH / MEDIUM / LOW severity levels
- **AI Analysis** — False positive filtering with Claude Sonnet
- **Automated Email Alerts** — For high-severity incidents
- **Incident Logging** — Persistent JSON-based audit trail
- **Multi-Value Field Handling** — Localization-aware (supports non-English Windows logs)
- **Machine Account Filtering** — Reduces false positives

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
