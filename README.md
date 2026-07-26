# AI-Powered SOC Automation Platform

A modular SOC automation platform built with **Splunk, Python, and Claude AI**. It detects threats mapped to **MITRE ATT&CK**, triages them through a cascading score-based pipeline, enriches indicators against live threat intelligence, retrieves precedent from past cases via a local vector store, escalates only high-risk events to an AI analyst, correlates multi-event kill-chains, hunts indicators across history, and logs everything to a tamper-evident hash-chain — end to end.

Each phase is documented on [Medium](https://erensaylan.medium.com/).

| Phase | What it added |
|:-----:|---------------|
| **1** | Brute-force detection with risk scoring, AI triage, SOAR skeleton |
| **2** | Index-time log normalization + a 12-rule MITRE ATT&CK engine, validated in an attack lab |
| **3** | 25 detections, score-based cascading triage, kill-chain correlation, tamper-evident hash-chain logging |
| **4** | Artifact-driven IOC enrichment (AbuseIPDB + OTX), IOC-aware triage, trend escalation, L1 throttling |
| **5** | Local semantic retrieval (L3 — ChromaDB), scope-aware knowledge base, enrichment-layer separation |
| **6** | IOC retro-hunting, static hunt library, investigation Cases, hash-chain-safe archival, read-only dashboard |

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
            │  + Knowledge Base check (known-legitimate)  │
            └─────────────────────────────────────────────┘
        │
        ▼   ┌─────────────────────────────────────────────┐
            │ L3  Semantic Retrieval — case memory        │
            │     ChromaDB (all-MiniLM-L6-v2, local)      │
            │     nearest past cases → context for L4     │
            └─────────────────────────────────────────────┘
        │
        ▼   ┌─────────────────────────────────────────────┐
            │ L4  Claude AI — per-event + kill-chain      │
            │     campaign analysis (MITRE + KB context)  │
            └─────────────────────────────────────────────┘
        │
        ▼   ┌─────────────────────────────────────────────┐
            │ L5  SOAR — email, hash-chain log,           │
            │     kill-chain correlation, retro-hunt,     │
            │     investigation Cases                     │
            └─────────────────────────────────────────────┘
        │
        ▼   ┌─────────────────────────────────────────────┐
            │  Read-only Streamlit dashboard (file-based) │
            │  chain health · MITRE · timeline · Cases    │
            └─────────────────────────────────────────────┘

```

## Features

**Detection & Triage**
- **25 MITRE ATT&CK detections** across 8 tactics (Sigma → SPL), with per-EventCode dedup so one action doesn't inflate into many events.
- **Cascading triage (L2)** — every event scored 0–100 on severity, technique weight, off-hours, critical-asset, IOC verdict, and kill-chain membership → ESCALATE / MONITOR / SUPPRESS. Only high scores spend an API call.
- **Kill-chain correlation** — events on the same user/host (or source IP) within a window are stitched into one campaign and analyzed as a single intrusion.

**Intelligence & Memory**
- **Artifact-driven IOC enrichment** — each indicator is queried once against AbuseIPDB + OTX, cached (1h TTL), reused across events. `malicious` → +20 score, `suspicious` → +10.
- **Semantic retrieval (L3)** — a local ChromaDB store (`all-MiniLM-L6-v2`, offline) surfaces the nearest past cases into Claude's prompt as precedent. Zero external calls.
- **Scope-aware knowledge base** — analyst-curated exceptions carry a scope: `infrastructure` (global) or `detection` (technique-scoped). A technique-scoped exception never silently widens — a narrow allowance can't become a blind spot.
- **Enrichment-layer separation** — IOC verdicts, AI reasoning, and asset data live in a dedicated `enrichment` block (schema v2.1); raw telemetry is never overwritten.

**Hunting & Investigation (Phase 6)**
- **IOC retro-hunt** — a `malicious`/`suspicious` verdict triggers a historical search across active + archived Splunk data, summarized per host with spread severity, hit-rate, duration, and MITRE context. `known_legitimate` indicators are skipped.
- **Static hunt library** — proactive, hypothesis-driven hunts (LOLBin downloaders, encoded PowerShell, Office-spawns-shell) run via `run_hunt.py`. Hunts, not detections — surfaced for analyst review.
- **Investigation Cases** — every kill-chain becomes a persistent Case with a deterministic Correlation UID, so the same chain always maps to the same Case and never duplicates. Cases reference incident IDs one-way — the hash-chain is never touched.

**Logging & Ops**
- **Tamper-evident hash-chain** — each incident is SHA-256-chained to the previous; any edit breaks the chain. Mutable aggregation fields (`count`, `last_seen`) are excluded from the payload so in-place updates don't break an append-only chain.
- **Hash-chain-safe archival** — old segments are archived only at gaps larger than the correlation window (no kill-chain split); a self-sealing *chain anchor* keeps the archive cryptographically linked without rewriting any hash.
- **Read-only dashboard** — a file-based Streamlit monitor (independent of Splunk): summary cards, live chain-integrity check, MITRE distribution, timeline, and Cases, with host masking for sharing.
- **Trend escalation, L1 throttling, email alerts, reasoning trace, token-optimized batching** — carried over from earlier phases.

---

## MITRE ATT&CK Coverage (25 detections)

| Tactic | Techniques | Validation |
|--------|-----------|:----------:|
| Initial Access | T1078 (External RDP / SMB / Failed-Logon reasons & source) | ✅ Lab |
| Execution | T1059 (MSHTA / Rundll32 / Stdin), T1059.001 PowerShell | ✅ Lab |
| Persistence | T1053.005, T1136.001, T1098, T1547.001 | ✅ Lab |
| Defense Evasion | T1070.001 🔴, T1055 🔴, T1562.001, T1027 | ✅ Lab |
| Credential Access | T1003.001 LSASS Dump | ✅ Lab |
| Discovery | T1057, T1083, T1012 · T1069 / T1082 (need DC) | ✅ Lab / Pattern |
| Lateral Movement | T1550.002 Pass-the-Hash, T1021.001 RDP | ✅ Lab / Pattern |
| Command & Control | T1105 Ingress Tool Transfer | ✅ Lab |

> **22 of 25 lab-validated** (fired end-to-end against real Atomic Red Team telemetry). Severity references Elastic Detection Rules + Sigma `level`, with independent adjustments (e.g. T1055 → CRITICAL). Coverage expands to 50+ (tactic-gap-targeted) in the next phase.

---

## Cascading Triage — Scoring Model (L2)

```
score = severity_base (CRITICAL 50 / HIGH 35 / MEDIUM 20 / LOW 10)
      + technique_weight        (T1070.001 & T1055 → 20, T1003.001 → 18, ... T1057/T1083/T1012 → 3)
      + ioc_enrichment          (malicious → 20, suspicious → 10)
      + monitor_accumulation    (3+ prior MONITOR on same detection/user/host → 15)
      + off_hours + critical_asset + breach_pattern + chain_member bonuses
```

| Route | Condition | Action |
|:-----:|-----------|--------|
| 🔴 ESCALATE | ≥ 60 | L4 Claude analysis + log + email (CRITICAL/HIGH) |
| 🟡 MONITOR | mid | Logged, watched, trend-tracked |
| 🟢 SUPPRESS | low | Auto-logged silently, never sent to AI |

Example — the same `T1078 External SMB Login`, scored three ways: **no artifact → 53 (MONITOR)**, **suspicious → 63 (ESCALATE)**, **malicious → 73 (ESCALATE)**.

---

## IOC Enrichment & Knowledge Base

Indicators are the unit of work, not events. Each IOC is extracted, checked against the knowledge base, then (if unknown) queried once against **AbuseIPDB + OTX**, cached, and reused. Private/loopback/link-local addresses and `known_legitimate` KB entries are skipped before any network call — sparing both the API request and a false alarm.

Verdict (max across sources): `≥80` malicious · `≥40` suspicious · `≥10` low-risk · else clean.

The knowledge base division of labor: IOC enrichment returns `known_legitimate` for matching infrastructure *before* any TI call; AI analysis injects in-scope KB entries as **verified ground truth** (distinct from the "may be unrelated" retrieval hints).

```bash
python3 kb_add.py --ip-prefix "100." --reason "Tailscale VPN range" --scope infrastructure
python3 kb_add.py --process "OneDriveSetup.exe" --techniques T1547.001 --scope detection
python3 kb_add.py --list
```

---

## Semantic Retrieval — Case Memory (L3)

Every new event and kill-chain is compared against past incidents; the nearest cases are injected into Claude's prompt as precedent, entirely locally.

- **Local & offline** — `all-MiniLM-L6-v2` on-device (~80 MB); incident data never leaves the box.
- **Index unique patterns, not raw rows** — the index unit is the unique `(technique_id, user, host)` pattern, collapsing thousands of near-identical rows into representative cases.
- **Asymmetric query vs document** — the stored document is rich (full analysis), the query is short (a live event has none yet), keeping distances meaningful.
- **No fixed distance threshold** — nearest cases are passed with an explicit "use your own judgment" note; a threshold will be measured once each technique has enough examples.

---

## Threat Hunting — Reactive + Proactive 

**Retro-hunt (reactive).** When enrichment flags an indicator, the pipeline asks *did this appear anywhere before?* — a field-targeted search across active + archived buckets (not a blind string match), summarized per host with spread severity (`[SPREAD]` / `[SINGLE]`), hit-rate, active duration, and MITRE context pulled from incident history. A per-run cache queries each indicator once.

```bash
python3 retro_hunt.py --ip <ip> --hash <sha256> --domain <domain> --earliest=-90d
```

**Static hunt library (proactive).** Hypothesis-driven hunts an analyst runs deliberately — **hunts, not detections** (no auto-alert, no incident write, no AI call).

| Hunt | Hypothesis |
|------|------------|
| H001 | certutil / bitsadmin used as a downloader (LOLBin abuse) |
| H002 | encoded / hidden PowerShell (`-enc`, `FromBase64String`, `-w hidden`) |
| H003 | an Office app spawning a shell (macro-based initial access) |

```bash
python3 run_hunt.py                 # all hunts
python3 run_hunt.py --hunt H002 --earliest=-24h
```

---

## Investigation Cases 

A kill-chain is ephemeral — recomputed every run. A **Case** promotes it to a persistent investigation object with a stable identity:

```
Correlation UID = "CASE-" + sha1(user | host | first_technique | day)[:12]
```

The UID is **deterministic** — the same chain gets the same Case no matter which run sees it, so re-running never duplicates. On re-sight, `upsert_case` merges: new incidents added, risk raised, techniques unioned, `seen_count` bumped. Cases live in a separate `logs/cases.json` and reference incident IDs one-way — **the hash-chain is never touched.** State changes (open → investigating → closed) and analyst notes are deferred to a later phase.

---

## Tamper-Evident Archival 

The incident log is re-read every run and can't grow forever — but records can't just be deleted (the chain would break, and correlation is sensitive to event count/timing). `archive_incidents.py` moves an old segment to `logs/archive/` and leaves a **chain anchor** at the head of the active file:

- **Cuts only at safe boundaries** — a gap larger than the correlation window, so no kill-chain is split.
- **The anchor is a header, not a link** — it carries `archived_last_hash` and seals *itself*; no existing hash is rewritten. `verify_chain()` resumes from the anchor; `verify_archive()` asserts the archive tail still matches it.

> **Found while building this:** 36 silent chain breaks — aggregation was mutating records in place (`count`, `last_seen`), incompatible with an append-only chain. The fix excludes those fields from the hash payload, repairing all of them **without rewriting a single hash.**

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| SIEM | Splunk Enterprise 9.3 |
| Backend / AI | Python 3.10 · Claude Sonnet 4.6 |
| Vector Store | ChromaDB (`all-MiniLM-L6-v2`, local/offline) |
| Dashboard | Streamlit + Plotly (read-only, file-based) |
| Detection Rules | Sigma → SPL (`sigma-cli`) |
| Attack Simulation | Atomic Red Team + Sysmon |
| Threat Intel | AbuseIPDB + OTX (AlienVault) |
| Infra | Ubuntu 22.04 · Windows 10/11 · Universal Forwarder · Oracle Cloud attack box over Tailscale |

---

## Quick Start

```bash
git clone https://github.com/thesaep/ai-soc-automation.git
cd ai-soc-automation
pip3 install -r requirements.txt
cp .env.example .env                 # fill in Splunk / Anthropic / email / TI keys
cp logs/knowledge_base.example.json logs/knowledge_base.json   # bootstrap KB

# deploy Splunk field extraction
cp splunk/local/*.conf /opt/splunk/etc/system/local/ && sudo -u splunk /opt/splunk/bin/splunk restart

python3 create_alerts.py             # register 25 detections as scheduled alerts
python3 soar_playbook.py             # run the pipeline
streamlit run dashboard.py           # (optional) monitoring dashboard — bind to 127.0.0.1 off-network
python3 run_hunt.py                  # (optional) proactive hunts
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
| `IOC_CACHE_TTL_HOURS` | IOC enrichment cache TTL in hours |


> Never commit `.env`. It is gitignored. Only `.env.example` (with placeholders) is tracked.

> **SPL gotcha:** backslash wildcards (`Image="*\certutil.exe"`) work in the Splunk UI but return nothing via REST — use `OriginalFileName` or command-line matching instead.

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
├── ai_analyzer.py               # Claude analyzer + batching + kill-chain + retrieval/KB context
├── soar_playbook.py             # Main orchestrator (detect → triage → enrich → retrieve → AI → log → correlate)
├── triage_scorer.py             # L2 cascading triage scorer (ESCALATE / MONITOR / SUPPRESS)
├── ioc_enricher.py              # AbuseIPDB + OTX enrichment, cache, IOC extraction, KB check
├── artifact_store.py            # Artifact CRUD, enrichment binding, pivot queries
├── semantic_retriever.py        # L3 ChromaDB indexing + retrieval (representatives, build_query/document)
├── knowledge_base.py            # Scope-aware exceptions (legitimate_tool + closed_case)
├── kb_add.py                    # CLI for fast knowledge-base entries (--scope: infrastructure/detection)
├── correlator.py                # Kill-chain correlation engine (user/host or source-IP based)
├── incident_logger.py           # Hash-chain logger (schema v2.1, archive anchor, verify_chain/archive)
├── archive_incidents.py         # Hash-chain-safe segment archival (dry-run by default)
├── retro_hunt.py                # IOC retro-hunt (auto + manual) + MITRE context
├── run_hunt.py                  # Static hypothesis-based hunt runner
├── case_manager.py              # Investigation Cases + deterministic Correlation UID
├── dashboard.py                 # Read-only Streamlit monitoring dashboard
├── create_alerts.py             # Creates/updates Splunk alerts (idempotent upsert)
├── mitre_context.json           # MITRE technique knowledge base for the AI layer
├── queries/
│   ├── brute_force.spl          # Detection (risk-scored)
│   ├── hunting/                 # Static hunt library (H001–H003)
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
├── logs/                        # gitignored — runtime state, per-deployment
│   ├── incidents.json           # Hash-chain incident log (schema v2.1, active segment)
│   ├── archive/                 # Archived incident segments + chain anchors
│   ├── cases.json               # Investigation Cases (Correlation UID)
│   ├── artifacts.json           # IOC artifacts with enrichment + seen_count
│   ├── ioc_cache.json           # Threat-intel cache (1h TTL)
│   ├── knowledge_base.json      # Scope-aware exceptions (analyst-curated)
│   ├── monitor_trend.json       # MONITOR accumulation counter (trend detection)
│   └── throttle_cache.json      # L1 throttle state (5min TTL, ephemeral)
├── logs/knowledge_base.example.json  # tracked — KB bootstrap template
├── chroma_db/                   # gitignored — local ChromaDB vector store (L3 index)
└── screenshots/                 # Project screenshots
```

---

## Screenshots

A selection is in [`screenshots/`](screenshots/): the SOAR pipeline and cascading triage, kill-chain correlation, semantic retrieval, the tamper-evident hash-chain, IOC enrichment and verdict-driven escalation, the scope-aware knowledge base resolving the Tailscale "C2" false positive, the monitoring dashboard with its live chain-integrity check, retro-hunt spread analysis, static hunts, and investigation Cases. Dashboard screenshots use the built-in host-masking toggle.

---

## Write-Ups

| Phase | Medium Article |
|-------|---------------|
| 1 | [Brute-force detection, risk scoring, AI triage, SOAR](https://erensaylan.medium.com/designing-an-ai-powered-soc-automation-platform-with-splunk-and-claude-ai-part-1-d75a173a5f2d) |
| 2 | [From one rule to a MITRE ATT&CK detection engine](https://medium.com/@erensaylan/designing-an-ai-powered-soc-automation-platform-with-splunk-and-claude-ai-part-2-169c67e4181b) |
| 3 | [Reasoning trace, kill-chain correlation, cascading triage](https://medium.com/@erensaylan/designing-an-ai-powered-soc-automation-platform-with-splunk-and-claude-ai-part-3-99d3292e9dfc) |
| 4 | [Artifact-driven IOC enrichment, IOC-aware triage, trend escalation](https://medium.com/@erensaylan/designing-an-ai-powered-soc-automation-platform-with-splunk-and-claude-ai-part-4-ecaded2d5d69) |
| 5 | [Semantic retrieval (L3), knowledge base, closing the "C2" false positive](https://medium.com/@erensaylan/designing-an-ai-powered-soc-automation-platform-with-splunk-and-claude-ai-part-5-cc2f331c92a5) |
| 6 | [IOC retro-hunting, hunt library, investigation Cases, tamper-evident archival, dashboard](https://erensaylan.medium.com/designing-an-ai-powered-soc-automation-platform-with-splunk-and-claude-ai-part-6-583163f7c42d) |

---

## License

MIT
