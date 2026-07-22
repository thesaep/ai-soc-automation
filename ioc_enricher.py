"""
ioc_enricher.py — Faz 7 IOC Enrichment
Artifact-driven: aynı IOC 1 kez sorgulanır (cache), N olaya bağlanabilir.
Kaynaklar: AbuseIPDB + OTX AlienVault
"""

import ipaddress
import os
import json
import time
import hashlib
import requests
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

# ── Sabitler ──────────────────────────────────────────────────────────────────
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_KEY       = os.getenv("OTX_API_KEY", "")
CACHE_TTL_H   = int(os.getenv("IOC_CACHE_TTL_HOURS", "1"))   # cache süresi (saat)
CACHE_FILE    = os.path.join(os.path.dirname(__file__), "logs", "ioc_cache.json")

# ── Cache yardımcıları ────────────────────────────────────────────────────────

def _load_cache() -> dict:
    """ioc_cache.json'dan cache'i yükle. Yoksa boş dict döndür."""
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict) -> None:
    """Cache'i diske yaz."""
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def _cache_key(ioc_type: str, value: str) -> str:
    """(type, value) → deterministik cache anahtarı."""
    raw = f"{ioc_type}:{value.lower()}"
    return hashlib.md5(raw.encode()).hexdigest()  # 32-char hex


def _cache_get(ioc_type: str, value: str) -> dict | None:
    """Cache'te varsa ve TTL dolmamışsa enrichment sonucunu döndür."""
    cache = _load_cache()
    key = _cache_key(ioc_type, value)
    entry = cache.get(key)
    if not entry:
        return None
    cached_at = datetime.fromisoformat(entry["cached_at"])
    if datetime.now(timezone.utc) - cached_at < timedelta(hours=CACHE_TTL_H):
        return entry["enrichment"]  # cache hit
    return None  # TTL dolmuş


def _cache_set(ioc_type: str, value: str, enrichment: dict) -> None:
    """Enrichment sonucunu cache'e yaz."""
    cache = _load_cache()
    key = _cache_key(ioc_type, value)
    cache[key] = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "ioc_type": ioc_type,
        "value": value,
        "enrichment": enrichment,
    }
    _save_cache(cache)


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def query_abuseipdb(ip: str) -> dict:
    """
    AbuseIPDB v2 API — IP itibar sorgusu.
    Döndürür: {score, country, isp, reports, is_whitelisted, tags, raw}
    score 0-100: 0=temiz, 100=tamamen kötü.
    """
    if not ABUSEIPDB_KEY:
        return {"error": "ABUSEIPDB_API_KEY eksik"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        d = resp.json().get("data", {})
        return {
            "source":         "abuseipdb",
            "score":          d.get("abuseConfidenceScore", 0),   # 0-100
            "country":        d.get("countryCode", "-"),
            "isp":            d.get("isp", "-"),
            "reports":        d.get("totalReports", 0),           # son 90 gün rapor sayısı
            "is_whitelisted": d.get("isWhitelisted", False),
            "usage_type":     d.get("usageType", "-"),
            "domain":         d.get("domain", "-"),
            "tags":           _abuseipdb_tags(d.get("abuseConfidenceScore", 0)),
        }
    except requests.RequestException as e:
        return {"source": "abuseipdb", "error": str(e)}


def _abuseipdb_tags(score: int) -> list[str]:
    """Score'a göre insan-okunabilir etiket üret."""
    if score >= 80:
        return ["malicious", "high-confidence"]
    if score >= 40:
        return ["suspicious"]
    if score >= 10:
        return ["low-risk"]
    return ["clean"]


# ── OTX AlienVault ────────────────────────────────────────────────────────────

def query_otx(ioc_type: str, value: str) -> dict:
    """
    OTX AlienVault — IP/domain/hash sorgusu.
    ioc_type: 'ip' | 'domain' | 'hash'
    Döndürür: {pulse_count, malware_families, tags, raw}
    """
    if not OTX_KEY:
        return {"error": "OTX_API_KEY eksik"}

    # OTX endpoint seçimi
    type_map = {
        "ip":     f"https://otx.alienvault.com/api/v1/indicators/IPv4/{value}/general",
        "domain": f"https://otx.alienvault.com/api/v1/indicators/domain/{value}/general",
        "hash":   f"https://otx.alienvault.com/api/v1/indicators/file/{value}/general",
    }
    url = type_map.get(ioc_type)
    if not url:
        return {"error": f"Desteklenmeyen IOC tipi: {ioc_type}"}

    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        d = resp.json()

        pulse_info = d.get("pulse_info", {})
        pulses     = pulse_info.get("pulses", [])

        # Malware ailelerini tüm pulse'lardan topla
        families = list({
            tag
            for p in pulses
            for tag in p.get("tags", [])
        })[:10]  # max 10 tag

        return {
            "source":          "otx",
            "pulse_count":     pulse_info.get("count", 0),  # kaç tehdit raporunda geçiyor
            "malware_families": families,
            "tags":            _otx_tags(pulse_info.get("count", 0)),
            "validation":      d.get("validation", []),
        }
    except requests.RequestException as e:
        return {"source": "otx", "error": str(e)}


def _otx_tags(pulse_count: int) -> list[str]:
    """Pulse count'a göre etiket üret."""
    if pulse_count >= 10:
        return ["malicious", "widely-reported"]
    if pulse_count >= 3:
        return ["suspicious"]
    if pulse_count >= 1:
        return ["low-risk"]
    return ["clean"]


# ── Ana enrichment fonksiyonu ─────────────────────────────────────────────────

def enrich_ioc(ioc_type: str, value: str, technique_id: str = None) -> dict:
    """
    Tek giriş noktası. ioc_type: 'ip' | 'domain' | 'hash'
    1. Cache kontrol → varsa döndür (API çağrısı yok)
    2. Yoksa API'leri sorgula → cache'e yaz → döndür

    Döndürür:
    {
        "ioc_type": "ip",
        "value": "1.2.3.4",
        "verdict": "malicious" | "suspicious" | "clean" | "unknown",
        "risk_score": 0-100,
        "sources": [abuseipdb_result, otx_result],
        "tags": [...],
        "cached": True/False,
        "enriched_at": "ISO8601"
    }
    """
    # Boş veya iç IP'leri atla
    if not value or value in ("-", "::1", "127.0.0.1"):
        return {"ioc_type": ioc_type, "value": value, "verdict": "skipped", "reason": "empty_or_local"}
    if ioc_type == "ip" and _is_private_ip(value):
        return {"ioc_type": ioc_type, "value": value, "verdict": "skipped", "reason": "private_ip"}
    # Faz 8.6: Knowledge Base scope-aware mesru-arac kontrolu (API'a gitmeden don)
    try:
        from knowledge_base import is_legitimate
        _kb_hit = None
        if ioc_type == "ip":
            _kb_hit = (is_legitimate(value, "ip_prefix", technique_id)
                       or is_legitimate(value, "ip", technique_id))
        elif ioc_type == "domain":
            _kb_hit = is_legitimate(value, "domain", technique_id)
        if _kb_hit:
            return {
                "ioc_type": ioc_type, "value": value,
                "verdict": "known_legitimate", "risk_score": 0,
                "reason": _kb_hit.get("reason", ""),
                "scope": _kb_hit.get("scope", "detection"),
                "kb_id": _kb_hit.get("kb_id"),
                "sources": [], "tags": ["known_legitimate"], "cached": False,
            }
    except Exception:
        pass

    # Cache kontrolü
    cached = _cache_get(ioc_type, value)
    if cached:
        cached["cached"] = True
        return cached

    # API sorguları
    results = []
    if ioc_type == "ip":
        results.append(query_abuseipdb(value))   # IP için her iki kaynak
        results.append(query_otx("ip", value))
    elif ioc_type == "domain":
        results.append(query_otx("domain", value))  # domain için sadece OTX
    elif ioc_type == "hash":
        results.append(query_otx("hash", value))    # hash için sadece OTX

    # Birleşik verdict ve risk_score hesapla
    verdict, risk_score, all_tags = _aggregate_verdict(results)

    enrichment = {
        "ioc_type":    ioc_type,
        "value":       value,
        "verdict":     verdict,      # malicious / suspicious / clean / unknown
        "risk_score":  risk_score,   # 0-100
        "sources":     results,
        "tags":        all_tags,
        "cached":      False,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }

    _cache_set(ioc_type, value, enrichment)
    return enrichment


def _aggregate_verdict(results: list[dict]) -> tuple[str, int, list[str]]:
    """
    Birden fazla kaynaktan gelen sonuçları birleştir.
    En yüksek skoru al, etiketleri topla.
    """
    max_score = 0
    all_tags  = []
    has_error = True

    for r in results:
        if "error" in r:
            continue
        has_error = False
        # AbuseIPDB skoru direkt 0-100
        if r.get("source") == "abuseipdb":
            max_score = max(max_score, r.get("score", 0))
        # OTX pulse count'u 0-100'e normalize et (10+ pulse = 100)
        elif r.get("source") == "otx":
            pulse_score = min(r.get("pulse_count", 0) * 10, 100)
            max_score = max(max_score, pulse_score)
        all_tags.extend(r.get("tags", []))

    if has_error:
        return "unknown", 0, []

    # Tag'leri deduplicate et
    all_tags = list(dict.fromkeys(all_tags))

    if max_score >= 80:
        verdict = "malicious"
    elif max_score >= 40:
        verdict = "suspicious"
    elif max_score >= 10:
        verdict = "low-risk"
    else:
        verdict = "clean"

    return verdict, max_score, all_tags


# ── Olaydan IOC çıkarma ───────────────────────────────────────────────────────

def extract_iocs_from_event(event: dict) -> list[dict]:
    """
    normalize_event() çıktısından IOC'leri çıkar.
    Döndürür: [{"type": "ip", "value": "1.2.3.4"}, ...]
    """
    iocs = []

    # Kaynak IP
    src_ip = event.get("src_ip", "-")
    if src_ip and src_ip not in ("-", "::1", "127.0.0.1", ""):
        if not _is_private_ip(src_ip):  # sadece dış IP'ler
            iocs.append({"type": "ip", "value": src_ip})

    # Hash (process image hash, dosya hash)
    for field in ("Hashes", "MD5", "SHA256", "SHA1"):
        val = event.get(field, "")
        if val and val != "-":
            # Splunk hash formatı: "SHA256=abc..." → değeri ayır
            if "=" in val:
                val = val.split("=")[-1].strip()
            if len(val) in (32, 40, 64):  # MD5=32, SHA1=40, SHA256=64
                iocs.append({"type": "hash", "value": val.lower()})
                break  # ilk geçerli hash yeterli

    # Domain (DNS sorgusu, network bağlantısı)
    for field in ("DestinationHostname", "QueryName", "domain"):
        val = event.get(field, "")
        if val and val not in ("-", "") and "." in val:
            if not _is_internal_domain(val):
                iocs.append({"type": "domain", "value": val.lower()})
                break

    return iocs


def _is_private_ip(ip: str) -> bool:
    """RFC1918 + loopback + link-local + IPv6 ULA kontrolu (ipaddress tabanli).

    NOT: 100.64.0.0/10 (CGNAT / Tailscale) bilerek PRIVATE SAYILMAZ.
    Faz 8.6 karari geregi Tailscale IP'leri gorunur kalir ve KB katmaninda
    downgrade edilir (audit izi korunur).
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _is_internal_domain(domain: str) -> bool:
    """İç domain kontrolü (.local, .corp, .internal vb.)."""
    internal_suffixes = (".local", ".corp", ".internal", ".lan", ".home")
    return any(domain.endswith(s) for s in internal_suffixes)


# ── Test ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[TEST] IOC Enricher - API connection test")
    print("-" * 50)

    # Test IP: bilinen kötü IP (AbuseIPDB test IP'si)
    test_ip = "185.220.101.1"  # Tor exit node, genellikle yüksek skor
    print(f"[1] IP sorgusu: {test_ip}")
    result = enrich_ioc("ip", test_ip)
    print(f"    Verdict: {result.get('verdict')} | Score: {result.get('risk_score')} | Tags: {result.get('tags')}")
    print(f"    Cached: {result.get('cached')}")

    # İkinci sorgu — cache'den gelmeli
    print(f"[2] Same IP again (cache test): {test_ip}")
    result2 = enrich_ioc("ip", test_ip)
    print(f"    Cached: {result2.get('cached')} <- should be True")

    # Private IP — skip olmalı
    print(f"[3] Private IP (skip testi): 192.168.1.1")
    result3 = enrich_ioc("ip", "192.168.1.1")
    print(f"    Verdict: {result3.get('verdict')} <- should be 'skipped'")

    print("-" * 50)
    print("[TEST] Completed")
