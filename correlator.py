"""
correlator.py — Faz 5: Multi-Event Korelasyon & Kill-Chain Detection

Bağımsız tespit edilen olayları, aynı saldırı kampanyasına ait olup olmadıklarına
göre zincirlere (kill-chain) gruplar. Her zincir, bir saldırganın bir hedef
üzerindeki koordineli aktivitesini temsil eder.

Tasarım notu (Faz 5-B hazırlığı):
  correlate_incidents() bir incident listesi alır — bu liste ister bu çalışmadaki
  taze olaylar, ister incidents.json'dan okunan geçmiş olaylar olabilir.
  Böylece Faz 5-B'de (stateful/geçmiş-farkındalıklı korelasyon) aynı fonksiyon
  kullanılır, sadece girdi kümesi genişler.
"""

from datetime import datetime, timezone


# MITRE ATT&CK kill-chain taktik sırası.
# Bir saldırı tipik olarak bu sırayla ilerler. Zincirdeki olayları
# bu sıraya göre dizerek "saldırı hangi aşamada" sorusunu cevaplarız.
KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Risk seviyelerinin sayısal karşılığı (zincir risk skoru hesabı için)
RISK_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "-": 0}
SCORE_RISK = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "UNKNOWN"}


def _parse_timestamp(ts: str) -> datetime:
    """
    ISO8601 timestamp string'ini timezone-aware datetime'a çevirir.
    Hatalı/eksik timestamp'lerde epoch döner (en eski) — sıralamada en başa düşer.
    """
    try:
        dt = datetime.fromisoformat(ts)
        # timezone yoksa UTC varsay
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _entity_key(incident: dict) -> tuple:
    """
    Bir incident'ın korelasyon anahtarını üretir.
    Öncelik: (user, host) → user yoksa (src_ip, host) → ikisi de yoksa (host,)
    Bu sayede kullanıcısız olaylar IP bazlı zincirlere girer.
    """
    entity = incident.get("entity", {})
    user   = entity.get("user", "-")
    host   = entity.get("host", "-")
    src_ip = entity.get("src_ip", "-")

    if user not in ("-", "", None):
        return (user, host)           # normal: kullanıcı bazlı
    elif src_ip not in ("-", "", None):
        return (src_ip, host)         # kullanıcı yok: IP bazlı
    else:
        return ("-", host)            # ikisi de yok: host bazlı


def _tactic_order_index(tactic: str) -> int:
    """
    Bir taktiğin kill-chain'deki sıra indeksini döndürür.
    Bilinmeyen taktik en sona düşer.
    """
    try:
        return KILL_CHAIN_ORDER.index(tactic)
    except ValueError:
        return len(KILL_CHAIN_ORDER)


def correlate_incidents(incidents: list, time_window_minutes: int = 60) -> list:
    """
    Incident listesini kill-chain zincirlerine gruplar.

    Algoritma:
      1. Olayları (user, host) anahtarına göre grupla
      2. Her grupta olayları zamana göre sırala
      3. time_window_minutes içindeki ardışık olayları aynı zincire koy
         (bir olay öncekinden bu süreden uzaksa yeni zincir başlar)

    Dönüş: zincir listesi. Her zincir bir dict:
      {
        "chain_id": "CHAIN-user-host-N",
        "entity": {"user", "host"},
        "incident_count": N,
        "incidents": [...],                    # zamana göre sıralı
        "tactics": [...],                       # kill-chain sırasına dizili benzersiz taktikler
        "techniques": [...],                    # teknik ID listesi
        "chain_risk": "CRITICAL",               # zincir geneli risk
        "time_span_minutes": float,             # ilk-son olay arası süre
        "is_multistage": bool,                  # 2+ farklı taktik varsa True
      }

    time_window_minutes: bir zinciri kıran boşluk eşiği. Varsayılan 60 dk.
      Faz 5-B'de geçmiş olaylar da dahil edilince bu pencere genişletilebilir.
    """
    if not incidents:
        return []

    # 1. (user, host) anahtarına göre grupla
    groups = {}
    for inc in incidents:
        key = _entity_key(inc)
        groups.setdefault(key, []).append(inc)

    chains = []
    window_seconds = time_window_minutes * 60

    for (user, host), group in groups.items():
        # 2. Zamana göre sırala
        group_sorted = sorted(group, key=lambda i: _parse_timestamp(i.get("timestamp", "")))

        # 3. Zaman penceresine göre alt-zincirlere böl
        current_chain = [group_sorted[0]]
        sub_chains = []

        for prev, curr in zip(group_sorted, group_sorted[1:]):
            gap = (_parse_timestamp(curr.get("timestamp", "")) -
                   _parse_timestamp(prev.get("timestamp", ""))).total_seconds()
            if gap <= window_seconds:
                current_chain.append(curr)
            else:
                # Boşluk çok büyük — yeni zincir başlat
                sub_chains.append(current_chain)
                current_chain = [curr]
        sub_chains.append(current_chain)

        # Her alt-zinciri yapılandır
        for idx, chain_incidents in enumerate(sub_chains, start=1):
            chains.append(_build_chain(user, host, chain_incidents, idx))

    # Zincirleri risk + olay sayısına göre sırala (en kritik en üstte)
    chains.sort(key=lambda c: (RISK_SCORE.get(c["chain_risk"], 0), c["incident_count"]),
                reverse=True)
    # Tek olaylı zincirleri filtrele — anlamsız, zaten tek başına olay
    chains = [c for c in chains if c["incident_count"] >= 2]
    return chains


def _build_chain(user: str, host: str, incidents: list, idx: int) -> dict:
    """
    Bir grup ilişkili incident'tan yapılandırılmış zincir objesi üretir.
    Kill-chain analizi, risk skoru ve metrikleri hesaplar.
    """
    # Benzersiz taktikleri kill-chain sırasına diz
    tactics_seen = []
    for inc in incidents:
        tactic = inc.get("mitre", {}).get("tactic", "Unknown")
        if tactic not in tactics_seen:
            tactics_seen.append(tactic)
    tactics_ordered = sorted(tactics_seen, key=_tactic_order_index)

    # Teknik ID'leri topla
    techniques = []
    for inc in incidents:
        tid = inc.get("mitre", {}).get("technique_id", "UNKNOWN")
        if tid not in techniques:
            techniques.append(tid)

    # Zincir risk skoru: en yüksek severity baz alınır
    max_risk_score = max((RISK_SCORE.get(inc.get("risk", "-"), 0) for inc in incidents),
                         default=0)
    # Çok-aşamalılık bonusu: 3+ farklı taktik = saldırı kampanyası, riski yükselt
    is_multistage = len(tactics_ordered) >= 2
    if len(tactics_ordered) >= 3 and max_risk_score < 4:
        max_risk_score += 1  # bir seviye yükselt (kümülatif risk)
    chain_risk = SCORE_RISK.get(min(max_risk_score, 4), "UNKNOWN")

    # Zaman aralığı
    timestamps = [_parse_timestamp(inc.get("timestamp", "")) for inc in incidents]
    time_span = (max(timestamps) - min(timestamps)).total_seconds() / 60 if len(timestamps) > 1 else 0.0

    return {
        "chain_id": f"CHAIN-{user.split(chr(92))[-1]}-{idx:03d}",
        "entity": {"user": user, "host": host},
        "incident_count": len(incidents),
        "incidents": incidents,
        "tactics": tactics_ordered,
        "techniques": techniques,
        "chain_risk": chain_risk,
        "time_span_minutes": round(time_span, 1),
        "is_multistage": is_multistage,
    }


def format_chain_summary(chain: dict) -> str:
    """
    Bir zinciri okunabilir özet metnine çevirir (terminal + AI prompt için).
    """
    lines = []
    lines.append(f"KILL-CHAIN: {chain['chain_id']}")
    lines.append(f"Hedef: {chain['entity']['user']} @ {chain['entity']['host']}")
    lines.append(f"Olay sayısı: {chain['incident_count']} | Zincir riski: {chain['chain_risk']}")
    lines.append(f"Zaman aralığı: {chain['time_span_minutes']} dakika")
    lines.append(f"Kill-chain aşamaları: {' -> '.join(chain['tactics'])}")
    lines.append(f"Teknikler: {', '.join(chain['techniques'])}")
    return "\n".join(lines)


if __name__ == "__main__":
    # Test modu: incidents.json'ı oku, korele et, zincirleri yazdır
    import json
    try:
        with open("logs/incidents.json", "r", encoding="utf-8") as f:
            incidents = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print("[-] incidents.json okunamadı")
        incidents = []

    chains = correlate_incidents(incidents, time_window_minutes=60)
    print(f"[+] {len(incidents)} incident -> {len(chains)} kill-chain\n")
    for chain in chains:
        print(format_chain_summary(chain))
        print("-" * 60)
