import os
from datetime import datetime


# ── Skorlama ağırlıkları (toplam teorik max ~140, 100'e clamp edilir) ──

# Severity → temel puan. Skorun çekirdeği.
SEVERITY_BASE = {
    "CRITICAL": 50,
    "HIGH":     35,
    "MEDIUM":   20,
    "LOW":      10,
    "-":        5,
}

# Teknik bazlı ek ağırlık. Bazı teknikler doğaları gereği daha tehlikeli.
# (Severity'den bağımsız ek sinyal — örn. log silme her zaman yüksek önem taşır.)
TECHNIQUE_WEIGHT = {
    "T1070": 20,   # Defense Evasion — iz silme, neredeyse her zaman kötü niyetli
    "T1550": 20,   # Pass-the-Hash — kimlik bilgisi suistimali
    "T1003": 18,   # Credential dumping
    "T1053": 12,   # Persistence — scheduled task
    "T1059": 12,   # Obfuscated execution
    "T1078": 10,   # Valid accounts
    "T1069": 5,    # Discovery
    "T1082": 3,    # Discovery
    "T1057": 3,    # Process Discovery — düşük, rutin recon
    "T1083": 3,    # File Discovery — düşük, rutin recon
    "T1012": 3,    # Registry Query — düşük, rutin recon
    "T1136": 12,   # Local Account Create — persistence
    "T1098": 12,   # Account Manipulation — persistence
}

# Kritik asset listesi. Bu host'lardaki olaylar daha yüksek öncelik alır.
# .env'den CRITICAL_ASSETS=DC01,SERVER01 şeklinde override edilebilir.
def _get_critical_assets():
    raw = os.getenv("CRITICAL_ASSETS", "")
    return [a.strip().upper() for a in raw.split(",") if a.strip()]


def _technique_prefix(technique_id: str) -> str:
    """T1070.001 → T1070 (ana teknik ID)."""
    return technique_id.split(".")[0] if technique_id else ""


def _is_off_hours(timestamp: str) -> bool:
    """
    Olay mesai dışında mı gerçekleşti? (Hafta sonu veya 08:00-18:00 dışı)
    Saldırganlar genelde mesai dışını tercih eder — bu bir risk sinyalidir.
    """
    try:
        dt = datetime.fromisoformat(timestamp)
        # Hafta sonu (5=Cumartesi, 6=Pazar)
        if dt.weekday() >= 5:
            return True
        # Mesai dışı saat
        if dt.hour < 8 or dt.hour >= 18:
            return True
        return False
    except (ValueError, TypeError):
        return False


def score_event(event: dict, in_chain: bool = False, chain_size: int = 1) -> dict:
    """
    Tek bir olaya risk skoru verir. Skor + gerekçe döndürür.

    event     : normalize edilmiş olay (user, host, src_ip, risk, detection_type, ...)
    in_chain  : olay bir kill-chain'in parçası mı (Faz 5 korelasyondan gelir)
    chain_size: zincirdeki olay sayısı (büyük zincir = daha yüksek risk)

    Dönüş:
      {
        "score": int (0-100),
        "verdict": "ESCALATE" | "MONITOR" | "SUPPRESS",
        "components": {...},   # her bileşenin katkısı (explainability)
        "route": "L4_claude" | "L2_autolog"  # nereye gidecek
      }
    """
    components = {}

    # 1. Severity temel puanı
    risk = event.get("risk", "-")
    base = SEVERITY_BASE.get(risk, 5)
    components["severity_base"] = base

    # 2. Teknik ağırlığı
    detection_type = event.get("detection_type", "")
    import re
    match = re.search(r"T\d{4}", detection_type)
    tech_prefix = match.group(0) if match else ""
    tech_weight = TECHNIQUE_WEIGHT.get(tech_prefix, 0)
    if tech_weight:
        components["technique_weight"] = tech_weight

    # 3. Asset kritikliği
    host = str(event.get("host", "")).upper()
    critical_assets = _get_critical_assets()
    if host in critical_assets:
        components["critical_asset"] = 15

    # 4. Mesai dışı bonusu
    timestamp = event.get("timestamp") or datetime.now().isoformat()
    if _is_off_hours(timestamp):
        components["off_hours"] = 8

    # 5. Davranışsal: başarılı + çok sayıda başarısız giriş (brute force success)
    try:
        failures = int(str(event.get("failures", "0")).replace("-", "0") or 0)
        successes = int(str(event.get("successes", "0")).replace("-", "0") or 0)
        if failures >= 10 and successes >= 1:
            components["breach_pattern"] = 15  # brute force sonrası başarılı giriş
        elif failures >= 20:
            components["high_volume_failures"] = 10
    except (ValueError, TypeError):
        pass

    # 6. Korelasyon bonusu: kill-chain'in parçası mı
    if in_chain and chain_size >= 2:
        # Zincir büyüdükçe bonus artar (max 20)
        chain_bonus = min(10 + (chain_size - 2) * 5, 20)
        components["chain_member"] = chain_bonus

    # Toplam skor (0-100 clamp)
    score = min(sum(components.values()), 100)

    # Verdict + routing
    threshold = int(os.getenv("TRIAGE_THRESHOLD", "60"))
    if score >= threshold:
        verdict = "ESCALATE"
        route = "L4_claude"          # Claude derin analizi
    elif score >= threshold - 25:
        verdict = "MONITOR"
        route = "L2_autolog"         # sadece logla, izle
    else:
        verdict = "SUPPRESS"
        route = "L2_autolog"         # düşük öncelik, logla

    return {
        "score": score,
        "verdict": verdict,
        "components": components,
        "route": route,
        "threshold": threshold,
    }


def triage_events(events: list, chains: list = None) -> dict:
    """
    Olay listesini L2 katmanından geçirir, L4'e gidecekleri ayırır.

    events : normalize edilmiş olay listesi
    chains : Faz 5 korelasyon çıktısı (opsiyonel) — zincir üyeliği skoru etkiler

    Dönüş:
      {
        "escalate": [...],    # L4 Claude'a gidecek olaylar (skor objesi eklenmiş)
        "autolog": [...],     # sadece loglanacak olaylar
        "scores": {...},      # her olayın skoru (incident_id veya index → skor)
        "stats": {...}        # özet istatistik
      }
    """
    # Hangi olaylar bir zincirde, zincir boyutu ne — hızlı lookup için map
    chain_membership = {}  # (user, host) → chain_size
    if chains:
        for chain in chains:
            entity = chain.get("entity", {})
            key = (entity.get("user", "-"), entity.get("host", "-"))
            chain_membership[key] = chain.get("incident_count", 1)

    escalate = []
    autolog = []
    scores = []

    for event in events:
        key = (event.get("user", "-"), event.get("host", "-"))
        in_chain = key in chain_membership
        chain_size = chain_membership.get(key, 1)

        result = score_event(event, in_chain=in_chain, chain_size=chain_size)
        scores.append(result)

        # Skoru olaya da iliştir (downstream kullanım için)
        event["_triage"] = result

        if result["route"] == "L4_claude":
            escalate.append(event)
        else:
            autolog.append(event)

    stats = {
        "total": len(events),
        "escalated": len(escalate),
        "autologged": len(autolog),
        "escalation_rate": round(len(escalate) / len(events) * 100, 1) if events else 0,
    }

    return {
        "escalate": escalate,
        "autolog": autolog,
        "scores": scores,
        "stats": stats,
    }


def format_triage_summary(result: dict) -> str:
    """Triage sonucunu okunabilir özet metnine çevirir."""
    stats = result["stats"]
    lines = []
    lines.append(f"L2 TRIAGE: {stats['total']} olay değerlendirildi")
    lines.append(f"  → ESCALATE (L4 Claude): {stats['escalated']} olay")
    lines.append(f"  → AUTO-LOG (L2):        {stats['autologged']} olay")
    lines.append(f"  → Escalation rate:      %{stats['escalation_rate']}")
    return "\n".join(lines)


if __name__ == "__main__":
    # Test: örnek olaylarla skorlama
    test_events = [
        {"user": "Goktug", "host": "DESKTOP-VNEKQ7O", "risk": "CRITICAL",
         "detection_type": "T1070.001 Event Log Cleared",
         "timestamp": "2026-06-08T03:00:00+00:00"},
        {"user": "normal", "host": "PC01", "risk": "MEDIUM",
         "detection_type": "T1069 LDAP Recon",
         "timestamp": "2026-06-08T14:00:00+00:00"},
    ]
    result = triage_events(test_events)
    print(format_triage_summary(result))
    print()
    for ev in test_events:
        t = ev["_triage"]
        print(f"{ev['detection_type'][:30]:32} skor={t['score']:3} {t['verdict']:10} {t['components']}")
