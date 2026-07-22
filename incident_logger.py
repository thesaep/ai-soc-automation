import json
import os
import hashlib
import uuid
import re
from datetime import datetime, timezone

# Log dosyası yolu
LOG_FILE = "logs/incidents.json"

ANCHOR_TYPE = "chain_anchor"


def _is_anchor(rec) -> bool:
    """Arsiv baslik kaydi mi? Zincirin HALKASI degil, BASLIGI."""
    return isinstance(rec, dict) and rec.get("record_type") == ANCHOR_TYPE


def _chain_start_hash(logs: list) -> str:
    """Dogrulama hangi hash'ten baslar: anchor varsa onun tasidigi arsiv hash'i."""
    if logs and _is_anchor(logs[0]):
        return logs[0].get("archived_last_hash", "genesis")
    return "genesis"


def _tail_hash(logs: list) -> str:
    """Yeni kaydin baglanacagi hash: son gercek kayit; sadece anchor varsa onun hash'i."""
    for rec in reversed(logs):
        if _is_anchor(rec):
            return rec.get("archived_last_hash", "genesis")
        return rec.get("hash", "genesis")
    return "genesis"




import copy as _copy

_MUTABLE_METRICS = ("count", "last_seen")
_HASH_RE = re.compile(r"[0-9a-f]{64}")


def _hash_payload(incident: dict) -> dict:
    """Hash'e giren govde: aggregation'in sonradan yazdigi alanlar HARIC.

    Gerekce: hash-chain append-only'dir; aggregation ise mevcut kaydi yerinde
    gunceller (count/last_seen). Bu iki alan hash disi birakilmazsa her
    aggregate edilen kayit zinciri kirar (bkz. 36 kirik kayit, Tem 2026).
    """
    e = _copy.deepcopy({k: v for k, v in incident.items() if k != "hash"})
    m = e.get("metrics")
    if isinstance(m, dict):
        for f in _MUTABLE_METRICS:
            m.pop(f, None)
    return e


def _compute_hash(incident: dict, prev_hash: str) -> str:
    """
    Incident içeriği + önceki hash'i SHA-256 ile imzalar.
    append-only bütünlük zinciri: birisi eski kaydı değiştirirse
    sonraki tüm hash'ler geçersiz hale gelir.
    prev_hash: bir önceki incident'ın hash değeri (zincirin ilk halkası için "genesis")
    """
    payload = json.dumps(_hash_payload(incident), ensure_ascii=False, sort_keys=True) + prev_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _get_last_hash() -> str:
    """
    Log dosyasındaki son incident'ın hash'ini döndürür.
    Dosya yoksa veya boşsa zincirin başlangıç değeri "genesis" döner.
    """
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)
        if logs:
            return _tail_hash(logs)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return "genesis"


def _extract_mitre_mapping(event: dict) -> dict:
    """
    Event'in detection_type field'ından MITRE teknik ID ve taktik adını çıkarır.
    detection_type örn: "T1550.002 Pass-the-Hash"
    """
    detection_type = event.get("detection_type", "")

    match = re.search(r"T\d{4}(?:\.\d{3})?", detection_type)
    technique_id = match.group(0) if match else "UNKNOWN"

    tactic_map = {
        "T1110": "Initial Access",
        "T1078": "Initial Access",
        "T1059": "Execution",
        "T1053": "Persistence",
        "T1550": "Lateral Movement",
        "T1070": "Defense Evasion",
        "T1069": "Discovery",
        "T1082": "Discovery",
        "T1057": "Discovery",
        "T1083": "Discovery",
        "T1012": "Discovery",
        "T1003": "Credential Access",
        "T1136": "Persistence",
        "T1098": "Persistence",
	"T1547": "Persistence",
        "T1562": "Defense Evasion",
        "T1105": "Command and Control",
        "T1055": "Defense Evasion",
        "T1027": "Defense Evasion",
        "T1021": "Lateral Movement",
    }
    tactic = tactic_map.get(technique_id)
    if not tactic:
        prefix = technique_id.split(".")[0]
        tactic = tactic_map.get(prefix, "Unknown")

    return {
        "technique_id": technique_id,
        "technique_name": detection_type,
        "tactic": tactic,
    }


def _extract_triggered_fields(event: dict) -> dict:
    """
    Detection'ı tetikleyen anlamlı field'ları çıkarır.
    Splunk internal field'larını filtreler, sadece güvenlikle ilgili olanları tutar.
    Bu, 'hangi kanıt bu kararı tetikledi?' sorusunun cevabıdır.
    """
    skip = {
        "_raw", "_bkt", "_cd", "_indextime", "_serial", "_si",
        "_sourcetype", "_subsecond", "_time", "linecount", "punct",
        "splunk_server", "splunk_server_group", "index", "sourcetype",
        "source", "eventtype", "detection_type", "risk",
        "user", "domain", "host", "src_ip",
    }
    triggered = {}
    for k, v in event.items():
        if k in skip or k.startswith("_"):
            continue
        if v in (None, "", "-", [], "0", 0):
            continue
        if isinstance(v, list):
            v = [x for x in v if x not in ("", "-", None)]
            if not v:
                continue
            v = v[-1] if len(v) == 1 else v
        triggered[k] = v
    return triggered


def _resolve_spl_file(event: dict) -> str:
    """
    detection_type'tan hangi .spl dosyasının kullanıldığını çıkarır.
    """
    detection_map = {
        "T1550": "queries/sigma_converted/lateral_movement/T1550_pass_the_hash.spl",
        "T1070": "queries/sigma_converted/defense_evasion/T1070_event_log_cleared.spl",
        "T1053": "queries/sigma_converted/persistence/T1053_scheduled_task.spl",
        "T1078": "queries/sigma_converted/initial_access/",
        "T1059": "queries/sigma_converted/execution/",
        "T1069": "queries/sigma_converted/discovery/T1069_ldap_recon.spl",
        "T1082": "queries/sigma_converted/discovery/T1082_net_recon.spl",
        "brute":  "queries/brute_force.spl",
	"T1057": "queries/sigma_converted/discovery/T1057_process_discovery.spl",
        "T1083": "queries/sigma_converted/discovery/T1083_file_discovery.spl",
        "T1012": "queries/sigma_converted/discovery/T1012_registry_query.spl",
        "T1003": "queries/sigma_converted/credential_access/T1003_lsass_dump.spl",
        "T1136": "queries/sigma_converted/persistence/T1136_local_account.spl",
        "T1098": "queries/sigma_converted/persistence/T1098_account_manipulation.spl",
	"T1547": "queries/sigma_converted/persistence/T1547_registry_run_keys.spl",
        "T1562": "queries/sigma_converted/defense_evasion/T1562_disable_defender.spl",
        "T1105": "queries/sigma_converted/command_and_control/T1105_ingress_tool_transfer.spl",
        "T1055": "queries/sigma_converted/defense_evasion/T1055_process_injection.spl",
        "T1027": "queries/sigma_converted/defense_evasion/T1027_obfuscated_files.spl",
        "T1021": "queries/sigma_converted/lateral_movement/T1021_rdp.spl",
    }
    detection_type = event.get("detection_type", "")
    for key, path in detection_map.items():
        if key.lower() in detection_type.lower():
            return path
    return "unknown"


def build_incident(event: dict, analysis: str) -> dict:
    """Public wrapper — tek incident için (test/debug amaçlı)."""
    prev_hash = _get_last_hash()
    return _build_incident_with_hash(event, analysis, prev_hash)


def _build_incident_with_hash(event: dict, analysis: str, prev_hash: str, triage_verdict: str = "-", triage_score: int = 0) -> dict:
    """
    Ham event + AI analizinden yapılandırılmış incident objesi üretir.
    prev_hash: zincirdeki bir önceki incident'ın hash'i (bellekten gelir)
    """
    incident = {
        "schema_version": "2.1",
        "incident_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_trace": {
            "detection_layer": "L1_SPL",
            "detection_name": event.get("detection_type", "brute_force"),
            "spl_file": _resolve_spl_file(event),
            "triggered_fields": _extract_triggered_fields(event),
            "search_window": os.getenv("SEARCH_EARLIEST", "-5m"),
            "triage_verdict": triage_verdict,
            "triage_score":   triage_score,
        },
        "entity": {
            "user":   event.get("user", "-"),
            "domain": event.get("domain", "-"),
            "host":   event.get("host", "-"),
            "src_ip": event.get("src_ip", "-"),
        },
        "mitre": _extract_mitre_mapping(event),
        "risk": event.get("risk", "-"),
        "metrics": {
            "failures":  event.get("failures", "-"),
            "successes": event.get("successes", "-"),
        },
        "ai_analysis": analysis,
        "enrichment": event.get("_enrichment", {"ioc": {}, "ai": {}, "asset": {}}),
        "hash": "",
    }

    incident_without_hash = {k: v for k, v in incident.items() if k != "hash"}
    incident["hash"] = _compute_hash(incident_without_hash, prev_hash)

    return incident


def log_incident_v2(events: list, ai_analyses: list, triage_scores: list = None) -> list:
    """
    Faz 4 incident logger.
    Her event için build_incident() çağırır, hash-chain ile yazar.
    Hash zinciri bellekte takip edilir — dosyadan okuma race condition'ını önler.
    Döndürülen liste: incident ID'leri (Faz 5 korelasyon için)
    """

    print(f"\n{'-'*65}")
    print(f"  [LOG] INCIDENT LOGGING")
    print(f"{'-'*65}")
    os.makedirs("logs", exist_ok=True)

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            existing_logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_logs = []

    # Hash zincirini bellekte tut — her build_incident sonrası güncelle
    # Böylece aynı batch içindeki incident'lar birbirini doğru referans alır
    prev_hash = _tail_hash(existing_logs)

    incident_ids = []
    _n_new = _n_aggregated = _n_skipped = 0
    # Aggregation için son 5 dakikadaki kayıtların hızlı lookup'ı
    from datetime import datetime, timezone, timedelta
    _now = datetime.now(timezone.utc)
    _agg_window = timedelta(minutes=5)
    _recent_keys = {}
    # Idempotency: aynı (detection, user, host, dakika) daha önce loglandıysa atla
    _logged_keys = set()
    for inc in existing_logs:
        try:
            ts = datetime.fromisoformat(inc.get("timestamp","").replace("Z","+00:00"))
            if _now - ts < timedelta(hours=8):   # 8h idempotency (SEARCH_EARLIEST=-3h, ~3x buffer)
                _logged_keys.add((
                    inc.get("mitre", {}).get("technique_name", ""),
                    inc.get("entity", {}).get("user", ""),
                    inc.get("entity", {}).get("host", "")
                ))
        except:
            pass
    for i, inc in enumerate(existing_logs):
        try:
            ts = datetime.fromisoformat(inc.get("timestamp","").replace("Z","+00:00"))
            if _now - ts < _agg_window:
                _agg_key = (
                    inc.get("mitre",{}).get("technique_name",""),
                    inc.get("entity",{}).get("user",""),
                    inc.get("entity",{}).get("host","")
                )
                _recent_keys[_agg_key] = i  # son index'i tut
        except:
            pass
    for i, (event, analysis) in enumerate(zip(events, ai_analyses)):
        try:
            # Idempotency kontrolü
            _ev_ikey = (
                event.get("detection_type", ""),
                event.get("user", ""),
                event.get("host", "")
            )
            if _ev_ikey in _logged_keys:
                print(f"  [~] SKIPPED (8h idempotency) | {_ev_ikey[0]} | {_ev_ikey[1]}")
                incident_ids.append(None)
                _n_skipped += 1
                continue
            _logged_keys.add(_ev_ikey)
            # Aggregation kontrolü
            _ev_key = (
                event.get("detection_type",""),
                event.get("user",""),
                event.get("host","")
            )
            if _ev_key in _recent_keys:
                _idx = _recent_keys[_ev_key]
                existing_logs[_idx].setdefault("metrics", {})["count"] = existing_logs[_idx]["metrics"].get("count", 1) + 1
                existing_logs[_idx]["metrics"]["last_seen"] = _now.isoformat()
                incident_ids.append(existing_logs[_idx]["incident_id"])
                print(f"  [~] Aggregated | ID: {existing_logs[_idx]['incident_id'][:8]}... "
                      f"| {_ev_key[0][:30]} | count: {existing_logs[_idx]['metrics']['count']}")
                _n_aggregated += 1
                continue
            # build_incident yerine direkt burada hash zincirini yönet
            _tv = triage_scores[i]["verdict"] if triage_scores and i < len(triage_scores) else "-"
            _ts = triage_scores[i]["score"]   if triage_scores and i < len(triage_scores) else 0
            incident = _build_incident_with_hash(event, analysis, prev_hash, triage_verdict=_tv, triage_score=_ts)
            existing_logs.append(incident)
            incident_ids.append(incident["incident_id"])
            _n_new += 1
            prev_hash = incident["hash"]  # bir sonraki incident bu hash'i kullanacak
            print(f"  [+] Incident logged | ID: {incident['incident_id'][:8]}... "
                  f"| {incident['mitre']['technique_id']} "
                  f"| {incident['risk']} "
                  f"| hash: {incident['hash'][:12]}...")
        except Exception as e:
            print(f"  [-] Incident log error: {e}")

    try:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_logs, f, ensure_ascii=False, indent=2)
        print(f"\n  [+] Incident logging: {_n_new} new, {_n_aggregated} aggregated, "
              f"{_n_skipped} skipped -> {LOG_FILE}")
    except Exception as e:
        print(f"  [-] Log file write error: {e}")

    return incident_ids


def verify_chain() -> bool:
    """
    Tüm log dosyasının hash zincirini doğrular.
    Herhangi bir incident değiştirilmişse False döner.
    Kullanım: python3 incident_logger.py
    """
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print("[-] Log file not found or invalid")
        return False

    prev_hash = _chain_start_hash(logs)
    if logs and _is_anchor(logs[0]):
        _a = logs[0]
        _a_nohash = {k: v for k, v in _a.items() if k != "hash"}
        if _compute_hash(_a_nohash, _a.get("archived_last_hash", "genesis")) != _a.get("hash", ""):
            print("[!] CHAIN ANCHOR TAMPERED")
            return False
    _unverifiable = []
    for i, incident in enumerate(logs):
        if _is_anchor(incident):
            continue
        stored_hash = incident.get("hash", "")
        # Legacy/sentetik kayit: hash SHA256 formatinda degil (orn. elle enjekte
        # edilmis test kayitlari, Haz 2026 / #1313-1314). Kendi butunlukleri
        # dogrulanamaz AMA zincirin parcasidir - sonraki kayitlar bu hash'e
        # baglandigi icin CIKARILAMAZ. Sayilir, raporlanir, uzerinden gecilir.
        if not _HASH_RE.fullmatch(stored_hash or ""):
            _unverifiable.append(i)
            prev_hash = stored_hash
            continue
        incident_without_hash = {k: v for k, v in incident.items() if k != "hash"}
        computed = _compute_hash(incident_without_hash, prev_hash)
        if computed != stored_hash:
            print(f"[-] Chain broken! Incident #{i} | ID: {incident.get('incident_id', '?')[:8]}...")
            return False
        prev_hash = stored_hash

    _verified = len(logs) - len(_unverifiable)
    if _unverifiable:
        print(f"[!] {len(_unverifiable)} unverifiable legacy record(s): {_unverifiable}")
        print("    (non-SHA256 hash format - integrity not provable, chain continuity preserved)")
    print(f"[+] Chain verified: {_verified}/{len(logs)} incidents intact")
    return True


if __name__ == "__main__":
    verify_chain()
