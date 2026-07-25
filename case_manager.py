#!/usr/bin/env python3
"""Faz 9.5 — Case nesnesi + Correlation UID.

Kill-chain zinciri gecicidir (her kosuda yeniden hesaplanir, chain_id kosu-ici
sirali numaradir). Case ise KALICI bir sorusturma nesnesidir: ayni zincir hangi
kosuda gorulurse gorulsun ayni Correlation UID'yi alir (deterministik).

Correlation UID = sha1(user | host | ilk_teknik | gun-bazli-pencere)[:12]
  - Idempotent: ayni zincir tekrar tekrar ayni Case'e duser, cogalmaz.
  - Gun-bazli pencere: ayni gun devam eden kampanya tek Case; farkli gun yeni Case.

Case'ler logs/cases.json'da saklanir (incidents.json'a DOKUNULMAZ — hash-chain
riski). Case, incident_id'leri REFERANS eder (tek yonlu bag). Turetilmis veri.

Durum degistirme (open/investigating/closed) + manuel not = Faz 11 (analyst
etiketleme). Bu fazda Case otomatik olusur, status='open' sabit.
"""
import json
import os
import hashlib
import datetime as dt

CASES_FILE = "logs/cases.json"


def _corr_uid(chain: dict) -> str:
    """Zincirden deterministik Correlation UID turet.

    Ayni (user, host, ilk-teknik, gun) her zaman ayni UID -> Case cogalmaz.
    chain_id KULLANILMAZ (o kosu-ici gecici numara).
    """
    ent = chain.get("entity", {})
    user = ent.get("user", "-")
    host = ent.get("host", "-")
    techs = chain.get("techniques", [])
    first_tech = techs[0] if techs else "-"
    # gun-bazli pencere: zincirin ilk incident zamanindan gun
    day = _chain_day(chain)
    raw = f"{user}|{host}|{first_tech}|{day}"
    return "CASE-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def _chain_day(chain: dict) -> str:
    """Zincirin ilk incident'inin gununu (YYYY-MM-DD) dondurur."""
    incs = chain.get("incidents", [])
    times = [i.get("timestamp", "") for i in incs if isinstance(i, dict) and i.get("timestamp")]
    if times:
        return min(times)[:10]
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")


def _load_cases() -> dict:
    try:
        with open(CASES_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_cases(cases: dict) -> None:
    os.makedirs(os.path.dirname(CASES_FILE), exist_ok=True)
    with open(CASES_FILE, "w", encoding="utf-8") as f:
        json.dump(cases, f, ensure_ascii=False, indent=2)


def upsert_case(chain: dict, ai_analysis: str = None) -> dict:
    """Zinciri Case'e cevirir. Varsa gunceller, yoksa olusturur (idempotent).

    Donen: guncel Case nesnesi.
    """
    uid = _corr_uid(chain)
    cases = _load_cases()
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    ent = chain.get("entity", {})

    inc_ids = [i.get("incident_id") for i in chain.get("incidents", [])
               if isinstance(i, dict) and i.get("incident_id")]

    if uid in cases:
        case = cases[uid]
        # birlesim: yeni incident'lari ekle (tekrarsiz), alanlari tazele
        existing = set(case.get("incident_ids", []))
        case["incident_ids"] = sorted(existing | set(inc_ids))
        case["incident_count"] = len(case["incident_ids"])
        case["techniques"] = sorted(set(case.get("techniques", [])) | set(chain.get("techniques", [])))
        case["tactics"] = _merge_tactics(case.get("tactics", []), chain.get("tactics", []))
        case["chain_risk"] = _max_risk(case.get("chain_risk", "LOW"), chain.get("chain_risk", "LOW"))
        case["time_span_minutes"] = max(case.get("time_span_minutes", 0), chain.get("time_span_minutes", 0))
        case["updated_at"] = now
        if ai_analysis:
            case["ai_analysis"] = ai_analysis
        case["seen_count"] = case.get("seen_count", 1) + 1
    else:
        case = {
            "correlation_uid": uid,
            "status": "open",                 # Faz 11: investigating/closed
            "entity": {"user": ent.get("user", "-"), "host": ent.get("host", "-")},
            "incident_ids": sorted(set(inc_ids)),
            "incident_count": len(set(inc_ids)),
            "techniques": chain.get("techniques", []),
            "tactics": chain.get("tactics", []),
            "chain_risk": chain.get("chain_risk", "LOW"),
            "time_span_minutes": chain.get("time_span_minutes", 0),
            "is_multistage": chain.get("is_multistage", False),
            "ai_analysis": ai_analysis or "",
            "retro_hunts": [],                # Faz 9.5: retro-hunt sonuclari buraya baglanabilir
            "created_at": now,
            "updated_at": now,
            "seen_count": 1,
        }
        cases[uid] = case

    _save_cases(cases)
    return case


_RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _max_risk(a: str, b: str) -> str:
    return a if _RISK_ORDER.get(a, 0) >= _RISK_ORDER.get(b, 0) else b


def _merge_tactics(a: list, b: list) -> list:
    """Kill-chain sirasini koruyarak taktikleri birlestir (tekrarsiz)."""
    seen, out = set(), []
    for t in list(a) + list(b):
        if t not in seen:
            seen.add(t); out.append(t)
    return out


def attach_retro_hunt(uid: str, ioc: str, retro: dict) -> bool:
    """Bir retro-hunt sonucunu ilgili Case'e bagla (Faz 9.5 opsiyonel bag)."""
    cases = _load_cases()
    if uid not in cases:
        return False
    cases[uid].setdefault("retro_hunts", []).append({
        "ioc": ioc,
        "host_count": retro.get("host_count", 0),
        "total_hits": retro.get("total_hits", 0),
        "attached_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    })
    cases[uid]["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    _save_cases(cases)
    return True


def list_cases(status: str = None) -> list:
    """Case'leri dondurur, opsiyonel status filtresi. En son guncellenen once."""
    cases = list(_load_cases().values())
    if status:
        cases = [c for c in cases if c.get("status") == status]
    return sorted(cases, key=lambda c: c.get("updated_at", ""), reverse=True)


if __name__ == "__main__":
    from semantic_retriever import load_incidents
    from correlator import correlate_incidents
    chains = correlate_incidents(load_incidents(), time_window_minutes=240)
    print(f"[*] {len(chains)} zincir -> Case'e cevriliyor")
    for ch in chains:
        c = upsert_case(ch)
        print(f"  {c['correlation_uid']} | {c['entity']['user']}@{c['entity']['host']} "
              f"| {c['incident_count']} incident | {len(c['techniques'])} teknik | {c['chain_risk']}")
    print(f"[+] Toplam {len(list_cases())} Case (logs/cases.json)")
