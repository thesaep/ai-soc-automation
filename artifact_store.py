"""
artifact_store.py — Faz 7.5 Artifact Katmanı
IOC atom nesnelerini yönetir: yarat, enrichment bağla, olayla ilişkilendir, pivot.
Schema: artifacts.json
"""

import os
import json
import uuid
from datetime import datetime, timezone
from ioc_enricher import extract_iocs_from_event, enrich_ioc

ARTIFACT_FILE = os.path.join(os.path.dirname(__file__), "logs", "artifacts.json")


# ── Dosya I/O ─────────────────────────────────────────────────────────────────

def _load_artifacts() -> list:
    """artifacts.json'dan tüm artifact'ları yükle."""
    try:
        with open(ARTIFACT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_artifacts(artifacts: list) -> None:
    """Artifact listesini diske yaz."""
    os.makedirs(os.path.dirname(ARTIFACT_FILE), exist_ok=True)
    with open(ARTIFACT_FILE, "w", encoding="utf-8") as f:
        json.dump(artifacts, f, ensure_ascii=False, indent=2)


# ── Artifact CRUD ─────────────────────────────────────────────────────────────

def _find_artifact(ioc_type: str, value: str, artifacts: list) -> dict | None:
    """Aynı (type, value) artifact varsa döndür, yoksa None."""
    value_lower = value.lower()
    for a in artifacts:
        if a["ioc_type"] == ioc_type and a["value"].lower() == value_lower:
            return a
    return None


def create_or_update_artifact(ioc_type: str, value: str, incident_id: str, technique_id: str = None) -> dict:
    """
    Artifact yoksa yarat, varsa incident_id ekle + last_seen güncelle.
    Enrichment'ı her zaman çek (cache'den gelir, API çağrısı olmaz).
    
    Döndürür: artifact nesnesi
    """
    artifacts = _load_artifacts()
    now = datetime.now(timezone.utc).isoformat()

    existing = _find_artifact(ioc_type, value, artifacts)

    if existing:
        # Varolan artifact — incident_id ekle, last_seen güncelle
        if incident_id and incident_id not in existing["incident_ids"]:
            existing["incident_ids"].append(incident_id)
        existing["last_seen"] = now
        existing["seen_count"] = existing.get("seen_count", 1) + 1
        # Enrichment'ı güncelle (cache'den gelir)
        enrichment = enrich_ioc(ioc_type, value, technique_id)
        if enrichment.get("verdict") != "skipped":
            existing["enrichment"] = enrichment
        _save_artifacts(artifacts)
        return existing
    else:
        # Yeni artifact — enrichment al, kaydet
        enrichment = enrich_ioc(ioc_type, value, technique_id)
        artifact = {
            "artifact_id":  str(uuid.uuid4()),
            "ioc_type":     ioc_type,       # ip / domain / hash
            "value":        value,
            "first_seen":   now,
            "last_seen":    now,
            "seen_count":   1,
            "incident_ids": [incident_id] if incident_id else [],
            "enrichment":   enrichment,     # verdict, risk_score, sources, tags
        }
        artifacts.append(artifact)
        _save_artifacts(artifacts)
        return artifact


def process_event_artifacts(event: dict, incident_id: str) -> list:
    """
    Tek olay için tüm IOC'leri çıkar, her biri için artifact yarat/güncelle.
    Döndürür: [artifact, ...] listesi
    """
    iocs = extract_iocs_from_event(event)
    results = []

    # Faz 8.6: olayin MITRE teknigini cikar -> enrich_ioc scope filtresine gecir
    _tech = ""
    try:
        import re as _re
        _m = _re.search(r"T\d{4}(?:\.\d{3})?", event.get("detection_type", "") or "")
        _tech = _m.group(0) if _m else ""
    except Exception:
        _tech = ""

    for ioc in iocs:
        artifact = create_or_update_artifact(ioc["type"], ioc["value"], incident_id, _tech)
        results.append(artifact)
        verdict = artifact["enrichment"].get("verdict", "unknown")
        score   = artifact["enrichment"].get("risk_score", 0)
        cached  = artifact["enrichment"].get("cached", False)
        if verdict == "known_legitimate":
            cache_str = "[KB]"
        elif cached:
            cache_str = "[CACHE]"
        else:
            cache_str = "[API]"
        print(f"  [ARTIFACT] {ioc['type'].upper()} {ioc['value']} "
              f"→ {verdict.upper()} (score:{score}) {cache_str}")

    return results


# ── Pivot sorguları ───────────────────────────────────────────────────────────

def get_artifact(ioc_type: str, value: str) -> dict | None:
    """Belirli bir IOC'nin artifact kaydını getir."""
    artifacts = _load_artifacts()
    return _find_artifact(ioc_type, value, artifacts)


def get_malicious_artifacts(min_score: int = 40) -> list:
    """risk_score >= min_score olan tüm artifact'ları getir."""
    artifacts = _load_artifacts()
    return [
        a for a in artifacts
        if a.get("enrichment", {}).get("risk_score", 0) >= min_score
    ]


def get_artifacts_by_incident(incident_id: str) -> list:
    """Belirli bir incident'a bağlı tüm artifact'ları getir."""
    artifacts = _load_artifacts()
    return [a for a in artifacts if incident_id in a.get("incident_ids", [])]


def get_artifact_summary() -> dict:
    """artifacts.json istatistik özeti."""
    artifacts = _load_artifacts()
    verdicts = {}
    for a in artifacts:
        v = a.get("enrichment", {}).get("verdict", "unknown")
        verdicts[v] = verdicts.get(v, 0) + 1
    return {
        "total":    len(artifacts),
        "verdicts": verdicts,
        "types":    {
            t: sum(1 for a in artifacts if a["ioc_type"] == t)
            for t in ("ip", "domain", "hash")
        },
    }


# ── Test ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[TEST] Artifact Store")
    print("-" * 50)

    # Test olayı — external IP içeriyor
    test_event = {
        "detection_type": "T1078 External SMB Login",
        "user":           "Goktug",
        "host":           "DESKTOP-VNEKQ7O",
        "src_ip":         "185.220.101.1",  # bilinen kötü IP
        "risk":           "HIGH",
    }

    print("[1] Extract artifact from event and enrich:")
    artifacts = process_event_artifacts(test_event, incident_id="test-incident-001")
    for a in artifacts:
        print(f"    artifact_id: {a['artifact_id'][:8]}... | "
              f"seen_count: {a['seen_count']}")

    print("[2] Same event again (seen_count should increase, from cache):")
    artifacts2 = process_event_artifacts(test_event, incident_id="test-incident-001")
    for a in artifacts2:
        print(f"    seen_count: {a['seen_count']} <- should be 2 | cached: {a['enrichment'].get('cached')}")

    print("[3] Summary:")
    summary = get_artifact_summary()
    print(f"    {summary}")

    print("-" * 50)
    print("[TEST] Completed")
