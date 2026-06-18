# AI-Powered SOC Automation Platform

A modular SOC automation platform built with Splunk, Python, and Claude AI. Detects threats mapped to **MITRE ATT&CK**, scores and triages them through a cascading pipeline, enriches indicators against live threat intelligence, escalates high-risk events to an AI SOC analyst, correlates multi-event kill-chains, and logs everything to a tamper-evident hash-chain — end to end.

Each phase is documented on [Medium](https://erensaylan.medium.com/).

> **Phase 1** detected brute force only.
> **Phase 2** added index-time log normalization and a 12-rule MITRE ATT&CK detection engine, validated in a dedicated attack-simulation lab.
> **Phase 3** turned it into a reasoning system: 25 detections, a score-based cascading triage layer, kill-chain correlation, and tamper-evident hash-chain logging.
> **Phase 4** gave it context: artifact-driven IOC enrichment (AbuseIPDB + OTX), IOC-aware triage, trend-based escalation, and an L1 throttling layer for continuous operation.

---

## Architecture — L1 → L5

Events flow through a cascading 5-layer pipeline. Each event only reaches the next layer if it survives the previous one — cheap filtering happens before expensive AI analysis.

```
Windows VM (Log Source: Security/System/Application + Sysmon)
        │
        ▼
Universal Forwarder ──► Ubuntu VM (Splunk Enterprise — index-time field normalization)
        │
        ▼   ┌─────────────────────────────────────────────┐
            │ L1  Detection — 25 MITRE ATT&CK SPL queries │
            └─────────────────────────────────────────────┘
        │
        ▼   ┌─────────────────────────────────────────────┐
            │ L2  Cascading Triage — score 0–100          │
            │     ESCALATE ≥60 → L4   MONITOR / SUPPRESS  │
            └─────────────────────────────────────────────┘
        │
        ▼   ┌─────────────────────────────────────────────┐
            │       IOC Enrichment — AbuseIPDB + OTX      │
            │  artifact-driven, cached → feeds L2 score   │
            └─────────────────────────────────────────────┘
        │
        ▼   ┌─────────────────────────────────────────────┐
            │ L3  Semantic Retrieval — case memory        │
            │     (planned, next phases — ChromaDB)       │
            └─────────────────────────────────────────────┘
        │
        ▼   ┌─────────────────────────────────────────────┐
            │ L4  Claude AI — per-event + kill-chain      │
            │     campaign analysis (MITRE context)       │
            └─────────────────────────────────────────────┘
        │
        ▼   ┌─────────────────────────────────────────────┐
            │ L5  SOAR — email alerts, hash-chain log,    │
            │     multi-event kill-chain correlation      │
            └─────────────────────────────────────────────┘

```

> **Why is L3 deferred?** Semantic retrieval surfaces precedent from *past* cases — which requires having past cases. Building it over an empty vector DB would be theater. L3 lands in next phases, once the incident dataset is mature.

---

## Features

- **Artifact-Driven IOC Enrichment** — every indicator (IP, hash, domain) is a first-class Artifact: extracted from events, queried once against AbuseIPDB + OTX, cached (1h TTL), and reused across events. Same IP in ten events = one Artifact with `seen_count: 10`, one API call.
- **IOC-Aware Triage** — artifact verdicts feed the L2 score: `malicious` adds +20, `suspicious` adds +10. A known-bad source IP auto-escalates an event internal signals alone would have held in MONITOR.
- **Trend-Based Escalation** (Phase 5-B) — repeated MONITOR verdicts on the same `(detection, user, host)` accumulate; 3+ adds +15, lifting a slow-burn pattern out of suppression.
- **L1 Alert Throttling** — a continuously-running (5-min cron) pipeline skips any `(detection, user, host)` processed within the last 5 minutes, via a dedicated ephemeral cache independent of incident logging. Stops re-processing persistent telemetry every cycle.
- **MITRE ATT&CK Detection Engine** — 25 detections across 8 tactics, converted from Sigma rules to SPL
- **Cascading Triage (L2)** — every event scored 0–100 on severity, technique weight, off-hours timing, critical-asset involvement, and kill-chain membership → routed to ESCALATE / MONITOR / SUPPRESS
- **Kill-Chain Correlation** — events on the same user/host within a time window are stitched into a campaign (`Execution → Persistence → Defense Evasion → ...`) and analyzed as one intrusion story
- **Tamper-Evident Hash-Chain Logging** — each incident is hash-chained to the previous one (blockchain-style); any post-hoc edit breaks the chain (schema v2.0)
- **Reasoning Trace** — every AI verdict is stored with its full rationale and pipeline metadata
- **Token-Optimized AI** — batch processing (8 events/call) + unique filtering (one event per `detection_type+user`) minimize Claude API usage
- **Brute Force Detection** — advanced detection rules with custom SPL and risk scoring (Phase 1)
- **Index-Time Log Normalization** — field extraction in Splunk `props.conf` (no per-query `rename`)
- **Automated Alert Management** — `create_alerts.py` creates/updates all Splunk alerts via REST API (idempotent upsert)
- **Automated Email Alerts** — for CRITICAL and HIGH severity incidents, with AI analysis in the body
- **Multi-Value Field Handling** — localization-aware (supports non-English Windows logs)
- **Machine Account Filtering** — reduces false positives
- **Attack-Simulation Lab** — detections validated with Atomic Red Team + Sysmon telemetry

---

## MITRE ATT&CK Coverage (25 detections)

| Tactic | Technique | Severity | Validation |
|--------|-----------|:--------:|:----------:|
| Initial Access | T1078 — External RDP Login | 🟠 HIGH | ✅ Lab |
| Initial Access | T1078 — External SMB Login | 🟠 HIGH | ✅ Lab |
| Initial Access | T1078 — Suspicious Failed Logon Reasons | 🟡 MEDIUM | ✅ Lab |
| Initial Access | T1078 — Suspicious Failed Logon Source | 🟡 MEDIUM | ✅ Lab |
| Execution | T1059 — Obfuscation via MSHTA | 🟠 HIGH | ✅ Lab |
| Execution | T1059 — Obfuscation via Rundll32 | 🟠 HIGH | ✅ Lab |
| Execution | T1059 — Obfuscation via Stdin | 🟠 HIGH | ✅ Lab |
| Execution | T1059.001 — PowerShell | 🟠 HIGH | ✅ Lab |
| Persistence | T1053.005 — Scheduled Task | 🟠 HIGH | ✅ Lab |
| Persistence | T1136.001 — Create Local Account | 🟠 HIGH | ✅ Lab |
| Persistence | T1098 — Account Manipulation | 🟠 HIGH | ✅ Lab |
| Persistence | T1547.001 — Registry Run Keys | 🟡 MEDIUM | ✅ Lab |
| Defense Evasion | T1070.001 — Clear Event Logs | 🔴 CRITICAL | ✅ Lab |
| Defense Evasion | T1055 — Process Injection | 🔴 CRITICAL | ✅ Lab |
| Defense Evasion | T1562.001 — Disable Defender | 🟠 HIGH | ✅ Lab |
| Defense Evasion | T1027 — Obfuscated Files | 🟡 MEDIUM | ✅ Lab |
| Credential Access | T1003.001 — LSASS Memory Dump | 🟠 HIGH | ✅ Lab |
| Discovery | T1057 — Process Discovery | 🟢 LOW | ✅ Lab |
| Discovery | T1083 — File & Directory Discovery | 🟢 LOW | ✅ Lab |
| Discovery | T1012 — Query Registry | 🟢 LOW | ✅ Lab |
| Discovery | T1069 — LDAP Recon | 🟡 MEDIUM | Requires DC |
| Discovery | T1082 — Network Recon | 🟢 LOW | Requires DC |
| Lateral Movement | T1550.002 — Pass-the-Hash | 🟠 HIGH | ✅ Lab |
| Lateral Movement | T1021.001 — RDP | 🟠 HIGH | Pattern |
| Command & Control | T1105 — Ingress Tool Transfer | 🟡 MEDIUM | ✅ Lab |

> **✅ Lab** = fired end-to-end against real telemetry (Atomic Red Team). **19 of 25 lab-validated.**

> **Pattern** = production-grade rule, validated against known attack patterns; needs an external IP / second host to fire in-lab.

> **Requires DC** = needs a Domain Controller to generate the relevant events.

Severity decisions reference Elastic Detection Rules and Sigma `level`, with some adjusted from independent research (e.g. T1055 pushed to CRITICAL — CreateRemoteThread injection is among the most dangerous techniques).

---

## Cascading Triage — Scoring Model (L2)

Every detected event is scored *before* it reaches the AI. Only high scores spend an API call.

```

score = severity_base
      + technique_weight      (T1070.001 → 20, T1055 → 20, T1003.001 → 18, T1562.001 → 15,
                               T1059* → 12, T1547.001 → 12, T1053.005 → 12, T1105 → 10,
                               T1021.001 → 10, T1027 → 5, T1057/T1083/T1012 → 3)
      + ioc_enrichment        (artifact malicious → 20, suspicious → 10)          
      + monitor_accumulation  (3+ prior MONITOR on same detection/user/host → 15) 
      + off_hours_bonus       (activity outside business hours)
      + critical_asset_bonus  (event touches a critical asset)
      + breach_pattern_bonus
      + chain_member_bonus    (event is part of a kill-chain)

```
| Route | Condition | Action |
|:-----:|-----------|--------|
| 🔴 ESCALATE | score ≥ 60 | L4 Claude analysis + log + (email if CRITICAL/HIGH) |
| 🟡 MONITOR | mid-range | Logged + watched |
| 🟢 SUPPRESS | low | Auto-logged, never sent to AI |

> **Brute-force** detections (Phase 1) still use count-based risk scoring (20+ failures, success correlation, etc.). MITRE detections use the technique-weighted triage above.

---

## IOC Enrichment Layer

Before an event is scored, its indicators are extracted and enriched against live threat intelligence. The design is artifact-driven: the indicator, not the event, is the unit of work.

```
Event → extract IOCs (IP / hash / domain)
      → Artifact created or updated   {type, value, first_seen, last_seen, seen_count, incident_ids}
      → cache check (1h TTL)
          ├── HIT  → reuse, zero API calls
          └── MISS → AbuseIPDB + OTX → cache
      → Enrichment attached   {verdict, risk_score, sources, tags}
      → verdict feeds L2 triage score
```
| Source | Indicator types | Signal |
|--------|-----------------|--------|
| **AbuseIPDB** | IP | 0–100 abuse-confidence score, report count, country, ISP |
| **OTX (AlienVault)** | IP, domain, hash | pulse count (threat-report references), malware families |

Verdict mapping (max across sources): `risk_score ≥ 80` → malicious · `≥ 40` → suspicious · `≥ 10` → low-risk · else clean. Private (RFC1918), loopback, and link-local addresses are skipped before any network call.

**Artifact verdict → triage bonus:**

| Verdict | Triage bonus | Effect |
|:-----:|-----------|--------|
| 🔴 MALICIOUS | +20 | often turns MONITOR into ESCALATE |
| 🟡 SUSPICIOUS | +10 | moderate push |
| 🟢 CLEAN/LOW-RISK | 0 | no change |

The same `T1078 External SMB Login`, scored three ways:

Artifact NONE:        45 → MONITOR
Artifact SUSPICIOUS:  55 → MONITOR
Artifact MALICIOUS:   65 → ESCALATE

Artifacts persist to `logs/artifacts.json` and support pivoting via `get_malicious_artifacts()`, `get_artifacts_by_incident()`, and `get_artifact_summary()`.


> **Cache pays off immediately.** First sighting of an IP costs one API call (`[API]`); every reuse in the same or subsequent runs is free (`[CACHE]`). At scale, where scanning IPs recur constantly, this keeps the pipeline inside free-tier quotas.

```

## Tech Stack

| Component | Technology |
|-----------|------------|
| SIEM | Splunk Enterprise 9.3 |
| Backend | Python 3.10 |
| AI | Claude Sonnet 4.6 (Anthropic) |
| Detection Rules | Sigma → SPL (`sigma-cli`) |
| Attack Simulation | Atomic Red Team + Sysmon |
| Server OS | Ubuntu Server 22.04 |
| Endpoint OS | Windows 10/11 |
| Log Forwarder | Splunk Universal Forwarder |
| Threat Intel | AbuseIPDB + OTX (AlienVault) |
| External Attack Box | Oracle Cloud VM (Frankfurt) over Tailscale |

---

## Screenshots

### SOAR Pipeline — Cascading Triage + Multi-Detection Analysis
![SOAR Pipeline](screenshots/soar_pipeline1.png)
![SOAR Pipeline](screenshots/soar_pipeline2.png)
![SOAR Pipeline](screenshots/soar_pipeline3.png)
![SOAR Pipeline](screenshots/soar_pipeline4.png)
![SOAR Pipeline](screenshots/soar_pipeline7.png)
The orchestration layer runs all 25 MITRE detections and Brute Force, scores each event through L2 triage, and sends only ESCALATE events to Claude AI. Severity banners (CRITICAL / HIGH) drive the response actions.

### Cascading Triage — Score-Based Routing
![Triage](screenshots/triage_scoring.png)
Each event gets a 0–100 score with a breakdown (severity, technique weight, off-hours, kill-chain membership) and is routed to L4-CLAUDE / MONITOR / AUTO-LOG.

### Kill-Chain Correlation
![Kill-Chain](screenshots/kill_chain.png)
Events on the same user/host are linked into a campaign and analyzed by Claude as a single intrusion (e.g. `Execution → Persistence → Defense Evasion → Command and Control`).

### Hash-Chain Incident Log
![Hash-Chain](screenshots/hash_chain.png)
Each incident is chained to the previous one via SHA-256. Tampering with any record breaks the chain.

### MITRE ATT&CK Alerts in Splunk
![MITRE Alerts](screenshots/mitre_alerts1.png)
![MITRE Alerts](screenshots/mitre_alerts2.png)
All detections registered as scheduled alerts (every 5 minutes), with per-technique severity.

### Claude AI — Attack-Chain Analysis
![AI Analysis](screenshots/ai_analysis1.png)
![AI Analysis](screenshots/ai_analysis2.png)
Claude analyzes each event with injected MITRE context and connects related events into a single coordinated intrusion.

### Attack Simulation — Atomic Red Team
![Atomic Red Team](screenshots/atomic_red_team.png)
Techniques simulated with Atomic Red Team and validated against the resulting Sysmon/Security telemetry in Splunk.

### Email Notification
![Email](screenshots/email1.png)
![Email](screenshots/email2.png)
Detailed automated email notifications for CRITICAL and HIGH severity events, with AI analysis and MITRE technique ID in the body.

### Incident Log File
![JSON](screenshots/incidents_json1.png)
All detected events are stored with timestamps and chained hashes in `logs/incidents.json`.

---

## Installation

**1. Clone & install dependencies**

```bash
git clone https://github.com/thesaep/ai-soc-automation.git
cd ai-soc-automation
pip3 install -r requirements.txt
```

**2. Configure environment**

```bash
cp .env.example .env
# Fill in your values
```

| Key | Description |
|-----|-------------|
| `SPLUNK_HOST` | Splunk server IP |
| `SPLUNK_PORT` | REST API port (default: 8089) |
| `SPLUNK_USERNAME` | Splunk username |
| `SPLUNK_PASSWORD` | Splunk password |
| `SPLUNK_URL` | Full URL (e.g. `https://localhost:8089`) |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `EMAIL_SENDER` | Gmail address |
| `EMAIL_PASSWORD` | Gmail app password |
| `EMAIL_RECEIVER` | Alert recipient |
| `SEARCH_EARLIEST` | Search window (e.g. `-3h`) |
| `TRIAGE_THRESHOLD` | Escalation cutoff (default: 60) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key (free tier: 1000 queries/day) |
| `OTX_API_KEY` | AlienVault OTX API key (free) |
| `IOC_CACHE_TTL_HOURS` | IOC enrichment cache TTL in hours


> Never commit `.env`. It is gitignored. Only `.env.example` (with placeholders) is tracked.

**3. Deploy Splunk field extraction**

```bash
cp splunk/local/props.conf /opt/splunk/etc/system/local/
cp splunk/local/transforms.conf /opt/splunk/etc/system/local/
sudo -u splunk /opt/splunk/bin/splunk restart
```

**4. Create detection alerts**

```bash
python3 create_alerts.py
```

Registers all 25 MITRE detections (+ brute force) as scheduled Splunk alerts (`*/5 * * * *`). Re-run any time you update a rule — idempotent upsert syncs the changes.

**5. Run the SOAR pipeline**

```bash
python3 soar_playbook.py
```

---

## Detection Rules (Sigma → SPL)

Community Sigma rules are converted to Splunk SPL:

```bash
sigma convert -t splunk -p splunk_windows <rule.yml> | tr -d '\r' > <rule.spl>
```

Each rule lives in `queries/sigma_converted/<tactic>/` and is loaded at runtime — never hardcoded in Python. Adding a technique means dropping a `.spl` file and adding one line to the detection list.

> **SPL gotcha (Phase 3):** backslash wildcards like `Image="*\certutil.exe"` work in the Splunk UI but silently return nothing through the REST API. Use command-line matching instead: `CommandLine="*certutil*"`.

---

## File Structure

```
ai-soc-automation/
├── README.md
├── .env
├── .env.example
├── .gitignore
├── requirements.txt
├── splunk_connector.py          # Splunk API connector + event normalization + 25 detections
├── ai_analyzer.py               # Claude analyzer + batching + kill-chain analysis
├── soar_playbook.py             # Main orchestrator (detection → triage → AI → log → correlate)
├── triage_scorer.py             # L2 cascading triage scorer
├── ioc_enricher.py              # AbuseIPDB + OTX enrichment, cache, IOC extraction
├── artifact_store.py            # Artifact CRUD, enrichment binding, pivot queries
├── correlator.py                # Kill-chain correlation engine
├── incident_logger.py           # Hash-chain incident logger (schema v2.0)
├── create_alerts.py             # Creates/updates Splunk alerts (idempotent upsert)
├── mitre_context.json           # MITRE technique knowledge base for the AI layer
├── queries/
│   ├── brute_force.spl          # Phase 1 detection (risk-scored)
│   └── sigma_converted/         # 25 Sigma → SPL MITRE rules
│       ├── command_and_control/
│       ├── credential_access/
│       ├── defense_evasion/
│       ├── discovery/
│       ├── execution/
│       ├── initial_access/
│       ├── lateral_movement/
│       └── persistence/
├── splunk/local/
│   ├── props.conf               # Field extraction (Phase 2 normalization)
│   └── transforms.conf
├── logs/
│   ├── incidents.json           # Hash-chain incident log
│   ├── artifacts.json           # IOC artifacts with enrichment + seen_count
│   ├── ioc_cache.json           # Threat-intel cache (1h TTL)
│   └── throttle_cache.json      # L1 throttle state (5min TTL, ephemeral)
└── screenshots/                 # Project screenshots
```

---

## Write-Ups

| Phase | Medium Article |
|-------|---------------|
| Phase 1 | [Brute-force detection, risk scoring, AI triage, SOAR](https://erensaylan.medium.com/designing-an-ai-powered-soc-automation-platform-with-splunk-and-claude-ai-part-1-d75a173a5f2d) |
| Phase 2 | [From one rule to a MITRE ATT&CK detection engine](https://medium.com/@erensaylan/designing-an-ai-powered-soc-automation-platform-with-splunk-and-claude-ai-part-2-169c67e4181b) |
| Phase 3 | [Reasoning trace, kill-chain correlation, cascading triage](https://medium.com/@erensaylan/designing-an-ai-powered-soc-automation-platform-with-splunk-and-claude-ai-part-3-99d3292e9dfc) |
| Phase 4 | [Artifact-driven IOC enrichment, IOC-aware triage, trend-based escalation](https://medium.com/@erensaylan/designing-an-ai-powered-soc-automation-platform-with-splunk-and-claude-ai-part-4-ecaded2d5d69) |

---

## Known Quirks (by design, not bugs)

- **The AI flags Tailscale as "C2 persistence".** When the tunnel installs itself via a `RunOnce` key (T1547.001), Claude correctly identifies remote-access-tool persistence as C2 behavior. It's right — it just doesn't know the analyst installed it. The proper fix is a knowledge/exception layer (next phase).
- **`SEARCH_EARLIEST=-3h` for manual testing.** Picks up the last 3 hours each run, so old telemetry resurfaces. Production cron should use `-5m`.
- **`nxc rdp` produces both RDP and SMB logons.** A single `nxc rdp` generates Type 10 (RDP) *and* Type 3 (SMB) logons because of the NLA handshake.

---

## License

MIT
