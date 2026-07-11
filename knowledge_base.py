"""
knowledge_base.py — Faz 8.6 Knowledge Base
İki kayıt tipi yönetir:
  1. legitimate_tool  — meşru-araç/altyapı istisnaları (Tailscale, OneDrive vb.)
  2. closed_case      — kapanmış vakalardan çıkarılan pattern/çözüm bilgisi

Amaç: AI ve triage'a "bu bilinen meşru aktivite" sinyali vererek false positive azaltmak.
Schema: logs/knowledge_base.json
"""

import os
import json
import uuid
from datetime import datetime, timezone

KB_FILE = os.path.join(os.path.dirname(__file__), "logs", "knowledge_base.json")


def _load_kb() -> list:
    try:
        with open(KB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_kb(entries: list) -> None:
    os.makedirs(os.path.dirname(KB_FILE), exist_ok=True)
    with open(KB_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)


def add_legitimate_tool(indicator: str, indicator_type: str, reason: str,
                        techniques: list = None, added_by: str = "analyst",
                        scope: str = "detection") -> dict:
    entries = _load_kb()
    for e in entries:
        if (e.get("kb_type") == "legitimate_tool"
                and e.get("indicator", "").lower() == indicator.lower()
                and e.get("indicator_type") == indicator_type):
            e["reason"] = reason
            e["techniques"] = techniques or e.get("techniques", [])
            e["scope"] = scope
            e["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_kb(entries)
            return e
    entry = {
        "kb_id":          str(uuid.uuid4()),
        "kb_type":        "legitimate_tool",
        "indicator":      indicator,
        "indicator_type": indicator_type,
        "reason":         reason,
        "techniques":     techniques or [],
        "scope":          scope,   # "infrastructure" (global) | "detection" (teknik-filtreli)
        "added_by":       added_by,
        "created_at":     datetime.now(timezone.utc).isoformat(),
    }
    entries.append(entry)
    _save_kb(entries)
    return entry


def is_legitimate(indicator: str, indicator_type: str = None,
                  technique_id: str = None) -> dict | None:
    """
    scope-aware mesru-arac kontrolu.
      scope="infrastructure" -> global, teknik-bagimsiz
      scope="detection"      -> sadece technique_id KB techniques listesindeyse gecerli;
                                technique_id yoksa detection-scope kayitlar ATLANIR (guvenli taraf)
    Eski (scope'suz) kayitlar guvenli tarafta = detection sayilir.
    """
    if not indicator:
        return None
    entries = _load_kb()
    ind_lower = indicator.lower()
    for e in entries:
        if e.get("kb_type") != "legitimate_tool":
            continue
        if indicator_type and e.get("indicator_type") != indicator_type:
            continue
        kb_ind = e.get("indicator", "").lower()
        itype = e.get("indicator_type")
        matched = False
        if itype == "ip_prefix":
            matched = ind_lower.startswith(kb_ind)
        elif itype == "process":
            matched = kb_ind in ind_lower
        else:
            matched = (ind_lower == kb_ind)
        if not matched:
            continue
        scope = e.get("scope", "detection")
        if scope == "infrastructure":
            return e
        kb_techs = e.get("techniques", [])
        if technique_id and (not kb_techs or technique_id in kb_techs):
            return e
    return None


def add_closed_case(incident_id: str, pattern: str, resolution: str,
                    techniques: list = None, added_by: str = "analyst") -> dict:
    entries = _load_kb()
    entry = {
        "kb_id":        str(uuid.uuid4()),
        "kb_type":      "closed_case",
        "incident_id":  incident_id,
        "pattern":      pattern,
        "resolution":   resolution,
        "techniques":   techniques or [],
        "added_by":     added_by,
        "created_at":   datetime.now(timezone.utc).isoformat(),
    }
    entries.append(entry)
    _save_kb(entries)
    return entry


def get_closed_cases(technique_id: str = None) -> list:
    entries = _load_kb()
    cases = [e for e in entries if e.get("kb_type") == "closed_case"]
    if technique_id:
        cases = [c for c in cases if technique_id in c.get("techniques", [])]
    return cases


def _extract_technique_id(detection_type: str) -> str:
    """detection_type string'inden MITRE teknik ID'sini cikar (orn. 'T1550.002')."""
    import re
    m = re.search(r"T\d{4}(?:\.\d{3})?", detection_type or "")
    return m.group(0) if m else ""


def get_kb_context_for_event(event: dict) -> list:
    """
    Bir olay icin ILGILI KB bilgisini topla (AI prompt'una enjekte edilir).
    scope-aware: is_legitimate icinde scope + technique filtresi uygulanir.
    """
    notes = []
    ev_tech = _extract_technique_id(event.get("detection_type", ""))
    # 1) Mesru altyapi (IP) — scope-aware
    src_ip = event.get("src_ip", "")
    if src_ip and src_ip not in ("-", ""):
        hit = (is_legitimate(src_ip, "ip_prefix", ev_tech)
               or is_legitimate(src_ip, "ip", ev_tech))
        if hit:
            scope_tag = hit.get("scope", "detection")
            notes.append({
                "type": "legitimate_infra",
                "note": f"Source IP {src_ip} is known legitimate ({scope_tag}): {hit['reason']}",
            })
    # 2) Mesru process (event'te Image/process alani varsa)
    proc = event.get("Image", "") or event.get("process", "") or event.get("NewProcessName", "")
    if proc:
        phit = is_legitimate(proc, "process", ev_tech)
        if phit:
            notes.append({
                "type": "legitimate_tool",
                "note": f"Process {proc} is known legitimate: {phit['reason']}",
            })
    # 3) Closed-case bilgisi — sadece olayin teknigine ait
    if ev_tech:
        for case in get_closed_cases(ev_tech):
            notes.append({
                "type": "closed_case",
                "note": f"[{case['resolution']}] {case['pattern']}",
            })
    return notes


def get_kb_summary() -> dict:
    entries = _load_kb()
    return {
        "total":            len(entries),
        "legitimate_tools": sum(1 for e in entries if e.get("kb_type") == "legitimate_tool"),
        "closed_cases":     sum(1 for e in entries if e.get("kb_type") == "closed_case"),
    }


if __name__ == "__main__":
    print("[TEST] Knowledge Base")
    print("-" * 50)
    print("[1] Tailscale IP prefix'i mesru olarak ekle:")
    e1 = add_legitimate_tool(
        indicator="100.",
        indicator_type="ip_prefix",
        reason="Tailscale VPN CGNAT range (100.64.0.0/10) - internal test infrastructure",
        techniques=["T1078", "T1550.002"],
    )
    print(f"    kb_id: {e1['kb_id'][:8]}... | {e1['indicator']} -> {e1['reason'][:50]}")
    print("[2] OneDrive process'ini mesru olarak ekle:")
    e2 = add_legitimate_tool(
        indicator="OneDriveSetup.exe",
        indicator_type="process",
        reason="Microsoft OneDrive update routine - writes RunOnce keys",
        techniques=["T1547.001"],
    )
    print(f"    kb_id: {e2['kb_id'][:8]}... | {e2['indicator']}")
    print("[3] is_legitimate testleri:")
    print(f"    100.109.237.72 -> {is_legitimate('100.109.237.72', 'ip_prefix') is not None}")
    print(f"    8.8.8.8        -> {is_legitimate('8.8.8.8', 'ip_prefix') is not None}")
    print("[4] Olay baglami (AI prompt enjeksiyonu):")
    test_ev = {"detection_type": "T1078 External SMB Login", "src_ip": "100.109.237.72"}
    for note in get_kb_context_for_event(test_ev):
        print(f"    [{note['type']}] {note['note']}")
    print("[5] Ozet:")
    print(f"    {get_kb_summary()}")
    print("-" * 50)
    print("[TEST] Tamamlandi")
