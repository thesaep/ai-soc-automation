import json
import os
import hashlib
import uuid
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
    # Hash'lenecek veri: incident içeriği + önceki hash
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
    Splunk'tan gelen raw field'lardan taktik bilgisi de eklenir.
    """
    detection_type = event.get("detection_type", "")

    # Teknik ID'yi çıkar (T + rakam + opsiyonel nokta + rakam)
    import re
    match = re.search(r"T\d{4}(?:\.\d{3})?", detection_type)
    technique_id = match.group(0) if match else "UNKNOWN"

    # Taktik → teknik ID'ye göre statik map (mitre_context.json olmadan da çalışsın)
    tactic_map = {
        "T1110": "Initial Access",
        "T1078": "Initial Access",
        "T1059": "Execution",
        "T1053": "Persistence",
        "T1550": "Lateral Movement",
        "T1070": "Defense Evasion",
        "T1069": "Discovery",
        "T1082": "Discovery",
    }
    # Tam ID'yi önce dene, yoksa prefix'e bak
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
    # Splunk internal / gürültülü field'lar
    skip = {
        "_raw", "_bkt", "_cd", "_indextime", "_serial", "_si",
        "_sourcetype", "_subsecond", "_time", "linecount", "punct",
        "splunk_server", "splunk_server_group", "index", "sourcetype",
        "source", "eventtype", "detection_type", "risk",
        "user", "domain", "host", "src_ip",  # zaten üst seviyede var
    }
    triggered = {}
    for k, v in event.items():
        if k in skip or k.startswith("_"):
            continue
        if v in (None, "", "-", [], "0", 0):
            continue
        # List ise join et
        if isinstance(v, list):
            v = [x for x in v if x not in ("", "-", None)]
            if not v:
                continue
            v = v[-1] if len(v) == 1 else v
        triggered[k] = v
    return triggered


def build_incident(event: dict, analysis: str) -> dict:
    """
    Ham event + AI analizinden yapılandırılmış incident objesi üretir.
    Bu fonksiyon Faz 4'ün çekirdeği: her sonraki faz bu şemayı kullanacak.

    Şema alanları:
      schema_version : gelecekteki şema değişikliklerinde eski logları parse etmek için
      incident_id    : UUID4 — her incident için global benzersiz ID
      timestamp      : UTC ISO8601 — timezone-aware, karşılaştırma için güvenli
      pipeline_trace : hangi katmandan geldi, hangi kural, hangi field'lar tetikledi
      entity         : kim/ne (user, domain, host, src_ip) — korelasyon anahtarları
      mitre          : ATT&CK teknik + taktik yapılandırılmış
      risk           : severity seviyesi
      ai_analysis    : Claude'un ürettiği analiz metni
      hash           : bu incident'ın + önceki hash'in SHA-256'sı (bütünlük zinciri)
    """
    incident = {
        "schema_version": "2.0",                          # Faz 4 şeması
        "incident_id": str(uuid.uuid4()),                  # Her incident için benzersiz ID
        "timestamp": datetime.now(timezone.utc).isoformat(), # UTC, timezone-aware

        # Pipeline trace: bu karar nasıl alındı?
        "pipeline_trace": {
            "detection_layer": "L1_SPL",                   # Faz 6'da L2/L3/L4 eklenecek
            "detection_name": event.get("detection_type", "brute_force"),
            "spl_file": _resolve_spl_file(event),          # Hangi .spl dosyası eşleşti
            "triggered_fields": _extract_triggered_fields(event),  # Kanıt field'ları
            "search_window": os.getenv("SEARCH_EARLIEST", "-5m"),  # Arama penceresi
        },

        # Entity: korelasyon için anahtar bilgiler (Faz 5'te bu field'lar üzerinden zincir kurulacak)
        "entity": {
            "user":   event.get("user", "-"),
            "domain": event.get("domain", "-"),
            "host":   event.get("host", "-"),
            "src_ip": event.get("src_ip", "-"),
        },

        # MITRE ATT&CK mapping: yapılandırılmış, aranabilir
        "mitre": _extract_mitre_mapping(event),

        # Risk ve sayısal metrikler
        "risk": event.get("risk", "-"),
        "metrics": {
            "failures":  event.get("failures", "-"),
            "successes": event.get("successes", "-"),
        },

        # AI analizi: ham metin olarak sakla, Faz 8'de label olarak kullanılacak
        "ai_analysis": analysis,

        # Hash: sonradan doldurulacak (_compute_hash için incident tamamlanmış olmalı)
        "hash": "",
    }

    # Hash'i hesapla (incident objesi tamamlandıktan sonra, hash field'ı hariç)
    incident_without_hash = {k: v for k, v in incident.items() if k != "hash"}
    prev_hash = _get_last_hash()
    incident["hash"] = _compute_hash(incident_without_hash, prev_hash)

    return incident


def _resolve_spl_file(event: dict) -> str:
    """
    detection_type'tan hangi .spl dosyasının kullanıldığını çıkarır.
    Faz 3'teki detection listesiyle uyumlu.
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
    }
    detection_type = event.get("detection_type", "")
    for key, path in detection_map.items():
        if key.lower() in detection_type.lower():
            return path
    return "unknown"


def log_incident_v2(events: list, ai_analyses: list) -> list:
    """
    Faz 4 incident logger. Her event için build_incident() çağırır,
    yapılandırılmış incident'ı hash-chain ile logs/incidents.json'a yazar.
    Döndürülen liste: oluşturulan incident ID'leri (Faz 5 korelasyon için)
    """
    os.makedirs("logs", exist_ok=True)

    # Mevcut logları yükle
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            existing_logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_logs = []

    incident_ids = []

    for event, analysis in zip(events, ai_analyses):
        try:
            incident = build_incident(event, analysis)
            existing_logs.append(incident)
            incident_ids.append(incident["incident_id"])

            # Terminal çıktısı
            print(f"  [+] Incident logged | ID: {incident['incident_id'][:8]}... "
                  f"| {incident['mitre']['technique_id']} "
                  f"| {incident['risk']} "
                  f"| hash: {incident['hash'][:12]}...")

        except Exception as e:
            print(f"  [-] Incident log hatası: {e}")

    # Tüm logları yaz
    try:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_logs, f, ensure_ascii=False, indent=2)
        print(f"\n  [+] {len(incident_ids)} incident yazıldı → {LOG_FILE}")
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
    # Zincir doğrulama modu
    verify_chain()
