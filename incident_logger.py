import json
import os
import hashlib
import uuid
import re
from datetime import datetime, timezone

# Log dosyası yolu
LOG_FILE = "logs/incidents.json"


def _compute_hash(incident: dict, prev_hash: str) -> str:
    """
    Incident içeriği + önceki hash'i SHA-256 ile imzalar.
    append-only bütünlük zinciri: birisi eski kaydı değiştirirse
    sonraki tüm hash'ler geçersiz hale gelir.
    prev_hash: bir önceki incident'ın hash değeri (zincirin ilk halkası için "genesis")
    """
    payload = json.dumps(incident, ensure_ascii=False, sort_keys=True) + prev_hash
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
            return logs[-1].get("hash", "genesis")
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


def _build_incident_with_hash(event: dict, analysis: str, prev_hash: str) -> dict:
    """
    Ham event + AI analizinden yapılandırılmış incident objesi üretir.
    prev_hash: zincirdeki bir önceki incident'ın hash'i (bellekten gelir)
    """
    incident = {
        "schema_version": "2.0",
        "incident_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_trace": {
            "detection_layer": "L1_SPL",
            "detection_name": event.get("detection_type", "brute_force"),
            "spl_file": _resolve_spl_file(event),
            "triggered_fields": _extract_triggered_fields(event),
            "search_window": os.getenv("SEARCH_EARLIEST", "-5m"),
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
        "hash": "",
    }

    incident_without_hash = {k: v for k, v in incident.items() if k != "hash"}
    incident["hash"] = _compute_hash(incident_without_hash, prev_hash)

    return incident


def log_incident_v2(events: list, ai_analyses: list) -> list:
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
    prev_hash = existing_logs[-1].get("hash", "genesis") if existing_logs else "genesis"

    incident_ids = []

    for event, analysis in zip(events, ai_analyses):
        try:
            # build_incident yerine direkt burada hash zincirini yönet
            incident = _build_incident_with_hash(event, analysis, prev_hash)
            existing_logs.append(incident)
            incident_ids.append(incident["incident_id"])
            prev_hash = incident["hash"]  # bir sonraki incident bu hash'i kullanacak
            print(f"  [+] Incident logged | ID: {incident['incident_id'][:8]}... "
                  f"| {incident['mitre']['technique_id']} "
                  f"| {incident['risk']} "
                  f"| hash: {incident['hash'][:12]}...")
        except Exception as e:
            print(f"  [-] Incident log hatası: {e}")

    try:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_logs, f, ensure_ascii=False, indent=2)
        print(f"\n  [+] {len(incident_ids)} incident yazıldı -> {LOG_FILE}")
    except Exception as e:
        print(f"  [-] Log dosyası yazma hatası: {e}")

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
        print("[-] Log dosyası bulunamadı veya geçersiz")
        return False

    prev_hash = "genesis"
    for i, incident in enumerate(logs):
        stored_hash = incident.get("hash", "")
        incident_without_hash = {k: v for k, v in incident.items() if k != "hash"}
        computed = _compute_hash(incident_without_hash, prev_hash)
        if computed != stored_hash:
            print(f"[-] Zincir kırık! Incident #{i} | ID: {incident.get('incident_id', '?')[:8]}...")
            return False
        prev_hash = stored_hash

    print(f"[+] Zincir doğrulandı: {len(logs)} incident, tümü sağlam")
    return True


if __name__ == "__main__":
    verify_chain()
