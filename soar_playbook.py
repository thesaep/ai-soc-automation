import re
import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv
import time
from incident_logger import log_incident_v2
from artifact_store import process_event_artifacts

load_dotenv()


def _get_technique_id(detection_type):
    m = re.search(r"T\d{4}(?:\.\d{3})?", detection_type)
    return m.group(0) if m else "-"

def send_email_alert(events, ai_analyses):
    """
    Yüksek riskli olaylar için email bildirimi gönderir.
    Sadece CRITICAL ve HIGH risklerde tetiklenir.
    """
    # events ve ai_analyses paralel listeler, zip ile beraber filtrele
    high_risk_pairs = [
        (e, a) for e, a in zip(events, ai_analyses) 
        if e.get('risk') in ['CRITICAL', 'HIGH']
    ]
    
    if not high_risk_pairs:
        return

    risks = [e.get('risk', 'HIGH') for e, _ in high_risk_pairs]
    top_risk = 'CRITICAL' if 'CRITICAL' in risks else 'HIGH'
    subject = f"[{top_risk}] SOC ALERT: {len(high_risk_pairs)} Yüksek Riskli Olay | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    body = f"""
SOC OTOMATIK UYARI SISTEMI
Tarih    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Toplam   : {len(high_risk_pairs)} yüksek riskli olay
{'='*60}
OLAY DETAYLARI
{'='*60}
"""
    for i, (event, analysis) in enumerate(high_risk_pairs):
        body += f"""
[{event.get('risk')}] OLAY #{i+1}
Detection    : {event.get('detection_type', '-')}
Kullanici    : {event.get('user', '-')}
Makine       : {event.get('host', '-')}
Kaynak IP    : {event.get('src_ip', '-')}
MITRE Teknik : {_get_technique_id(event.get('detection_type',''))}
AI ANALIZI:
{analysis}
{'-'*60}
"""

    try:
        msg = MIMEMultipart()
        msg['From'] = os.getenv("EMAIL_SENDER")
        msg['To'] = os.getenv("EMAIL_RECEIVER")
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain', 'utf-8'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(
                os.getenv("EMAIL_SENDER"),
                os.getenv("EMAIL_PASSWORD")
            )
            server.send_message(msg)
    
    except Exception as e:
        print(f"\n  [-] Email gönderilemedi: {e}")


if __name__ == "__main__":
    from splunk_connector import connect_splunk, get_brute_force_events, get_all_mitre_events
    from ai_analyzer import analyze_with_claude, analyze_chain_with_claude
    from correlator import correlate_incidents, format_chain_summary
    from incident_logger import log_incident_v2
    from artifact_store import process_event_artifacts
    from triage_scorer import triage_events, format_triage_summary

    start_time = time.time()
    service = connect_splunk()
    if service:
        # L1: Detection (Faz 1 + Faz 3)
        bf_events = get_brute_force_events(service, threshold=5)
        mitre_events = get_all_mitre_events(service, earliest=os.getenv("SEARCH_EARLIEST", "-5m"))
        all_events = bf_events + mitre_events

        # L1 Throttling (Faz 7) — son 5dk'da aynı (detection,user,host) ESCALATE olduysa atla
        import json as _tjson
        from datetime import datetime as _tdt, timezone as _ttz, timedelta as _ttd
        _throttle_keys = set()
        try:
            with open("logs/incidents.json", "r", encoding="utf-8") as _tf:
                _tinc = _tjson.load(_tf)
            _t_cutoff = (_tdt.now(_ttz.utc) - _ttd(minutes=5)).isoformat()
            for _ti in _tinc:
                if _ti.get("timestamp","") >= _t_cutoff:
                    _throttle_keys.add((
                        _ti.get("pipeline_trace",{}).get("detection_name",""),
                        _ti.get("entity",{}).get("user","-"),
                        _ti.get("entity",{}).get("host","-")
                    ))
        except Exception:
            pass
        _before = len(all_events)
        all_events = [
            e for e in all_events
            if (e.get("detection_type",""), e.get("user","-"), e.get("host","-")) not in _throttle_keys
        ]
        _throttled = _before - len(all_events)
        if _throttled > 0:
            print(f"  [THROTTLE] {_throttled} olay son 5dk'da zaten islendi — atlandi")

        if not all_events:
            print("\n  [*] Şüpheli olay bulunamadı")
        else:
            # Korelasyon için önce mevcut incident geçmişini yükle (zincir üyeliği skoru etkiler)
            try:
                with open("logs/incidents.json", "r", encoding="utf-8") as f:
                    history = json.load(f)
            except Exception:
                history = []
            prelim_chains = correlate_incidents(history + all_events, time_window_minutes=60)

            # L2: Cascading triage — hangi olaylar Claude'a gidecek?
            print(f"\n{'='*65}")
            print(f"  [TRIAGE]  L2 CASCADING TRIAGE")
            print(f"{'='*65}")
            # Faz 7.5: Artifact verdict map — src_ip → verdict (cache'den, API yok)
            from artifact_store import get_artifact
            _artifact_verdicts = {}
            for _ev in all_events:
                _ip = _ev.get("src_ip", "")
                if _ip and _ip not in _artifact_verdicts:
                    _art = get_artifact("ip", _ip)
                    if _art:
                        _artifact_verdicts[_ip] = _art.get("enrichment", {}).get("verdict", None)

            # Faz 5-B: Monitor birikim sayacı — incidents.json'dan hesapla
            import json as _json
            _monitor_counts = {}
            try:
                with open("logs/incidents.json", "r", encoding="utf-8") as _f:
                    _all_inc = _json.load(_f)
                from datetime import datetime as _dt, timezone as _tz, timedelta as _td
                _cutoff = (_dt.now(_tz.utc) - _td(days=7)).isoformat()
                for _inc in _all_inc:
                    if _inc.get("timestamp","") < _cutoff:
                        continue
                    if _inc.get("triage_verdict") == "MONITOR":
                        _mk = (
                            _inc.get("pipeline_trace",{}).get("detection_name",""),
                            _inc.get("entity",{}).get("user","-"),
                            _inc.get("entity",{}).get("host","-")
                        )
                        _monitor_counts[_mk] = _monitor_counts.get(_mk, 0) + 1
            except Exception:
                pass

            triage = triage_events(all_events, chains=prelim_chains,
                                   artifact_verdicts=_artifact_verdicts,
                                   monitor_counts=_monitor_counts)
            escalate_events = triage["escalate"]
	    # Unique filtre: aynı detection_type + user kombinasyonu varsa sadece birini analiz et
            # Duplike olaylar token israfı yaratır — tekilleştir, geri kalanları autolog'a taşı
            seen = set()
            unique_escalate = []
            duplicate_escalate = []
            for ev in escalate_events:
                key = (ev.get('detection_type', ''), ev.get('user', ''))
                if key not in seen:
                    seen.add(key)
                    unique_escalate.append(ev)
                else:
                    duplicate_escalate.append(ev)
            if duplicate_escalate:
                print(f"  [i] {len(duplicate_escalate)} duplike olay AUTO-LOG'a tasindi "
                      f"— ayni teknik+kullanici kombinasyonu zaten analiz edildi (token tasarrufu)")
            autolog_events = triage["autolog"] + duplicate_escalate
            escalate_events = unique_escalate
            _duplicate_ids = {id(ev) for ev in duplicate_escalate}
            # Unique filtre sonrası doğru stats özeti
            _total = len(all_events)
            _esc_unique = len(unique_escalate)
            _esc_dup = len(duplicate_escalate)
            _autolog = len(triage["autolog"])
            _esc_rate = int((_esc_unique / _total * 100)) if _total > 0 else 0
            print(f"L2 TRIAGE: {_total} olay degerlendirildi")
            print(f"  -> ESCALATE (L4 Claude): {_esc_unique} olay (+ {_esc_dup} duplike AUTO-LOG'a tasindi)")
            print(f"  -> AUTO-LOG (L2):        {_autolog} olay")
            print(f"  -> Escalation rate:      %{_esc_rate}")
            # Triage print — aynı (detection, user, host) kombinasyonunu aggregated göster
            from collections import OrderedDict
            _print_groups = OrderedDict()
            for _ev, _sc in zip(all_events, triage["scores"]):
                _pk = (_ev.get("detection_type",""), _ev.get("user",""), _ev.get("host",""))
                # Tüm kararlar (ESCALATE dahil) aynı (detection,user,host) key ile aggrege edilir
                # is_dup flag'i ile print sırasında L4-CLAUDE vs DUPLIKE-LOG ayrımı yapılır
                if _pk not in _print_groups:
                    _print_groups[_pk] = {"ev": _ev, "sc": _sc, "count": 1, "is_dup": False}
                else:
                    _print_groups[_pk]["count"] += 1
            _i = 0
            for _pk, _grp in _print_groups.items():
                _i += 1
                ev, sc = _grp["ev"], _grp["sc"]
                count = _grp["count"]
                count_str = f" x{count}" if count > 1 else ""
                if sc["verdict"] == "ESCALATE" and _grp.get("is_dup", False):
                    karar = "-> DUPLIKE-LOG"
                else:
                    karar = {"ESCALATE": "-> L4-CLAUDE", "MONITOR": "-> IZLE", "SUPPRESS": "-> AUTO-LOG"}.get(sc["verdict"], sc["verdict"])
                neden_parts = []
                if "severity_base" in sc["components"]:
                    risk = ev.get("risk", "-")
                    neden_parts.append(f"{risk} severity")
                if "technique_weight" in sc["components"]:
                    w = sc["components"]["technique_weight"]
                    if w >= 15:
                        neden_parts.append(f"kritik teknik (agirlik:{w})")
                    elif w >= 10:
                        neden_parts.append(f"orta riskli teknik (agirlik:{w})")
                    else:
                        neden_parts.append(f"dusuk riskli teknik (agirlik:{w})")
                if "off_hours" in sc["components"]:
                    neden_parts.append(f"mesai disi")
                if "critical_asset" in sc["components"]:
                    neden_parts.append(f"kritik asset")
                if "breach_pattern" in sc["components"]:
                    neden_parts.append(f"ihlal pattern (cok basarisiz+basarili)")
                if "chain_member" in sc["components"]:
                    neden_parts.append(f"kill-chain uyesi")
                neden = " | ".join(neden_parts)
                print(f"  #{_i:<2} {ev.get('detection_type','?')[:35]:<35} | "
                      f"Skor:{sc['score']:3}/100 | "
                      f"{karar:<14}{count_str:<6} | {neden}")


            # L4: Sadece ESCALATE olanlar Claude'a gider
            if escalate_events:
                print(f"\n  -> {len(escalate_events)} olay L4 (Claude) analizine yükseltildi")
                ai_analyses = analyze_with_claude(escalate_events, return_results=True)
            else:
                print(f"\n  -> Hiçbir olay eşiği geçmedi, L4 atlandı (token tasarrufu)")
                ai_analyses = []

            # Auto-log olanlar için Claude analizi yerine placeholder
            autolog_analyses = ["[L2 AUTO-LOG] Skor eşiği altında, otomatik loglandı, izlemede."
                                for _ in autolog_events]

            # Tüm olayları logla (escalate + autolog), sırayı koru
            combined_events = escalate_events + autolog_events
            combined_analyses = ai_analyses + autolog_analyses
            incident_ids = log_incident_v2(combined_events, combined_analyses)
            # Faz 7: Artifact-driven IOC enrichment — sadece ESCALATE olaylar
            print(f"\n  [ARTIFACT] IOC enrichment basliyor ({len(escalate_events)} ESCALATE olay)...")
            for ev, inc_id in zip(escalate_events, incident_ids[:len(escalate_events)]):
                # Artifact enrichment: inc_id None olsa bile çalış (seen_count + triage sinyal)
                # inc_id None = idempotency skip, ama IOC pivot verisi yine güncellenmeli
                process_event_artifacts(ev, inc_id)

            # Faz 5: Korelasyon — güncel incident geçmişiyle zincirleri çıkar
            try:
                with open("logs/incidents.json", "r", encoding="utf-8") as f:
                    all_incidents = json.load(f)
            except Exception:
                all_incidents = []
            # Korelasyon için sadece son 7 günün incident'larını kullan — performans optimizasyonu
            from datetime import datetime, timezone, timedelta
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            recent_incidents = [i for i in all_incidents if i.get("timestamp", "") >= cutoff]
            chains = correlate_incidents(recent_incidents, time_window_minutes=240) # 4h — APT lateral movement kapsamı genişletildi (Faz 6 sonrası)

            if chains:
                print(f"\n{'='*65}")
                print(f"  [CHAIN] KORELASYON: {len(all_incidents)} olay ({len(all_events)} yeni) -> {len(chains)} zincir")
                print(f"{'='*65}")
                # Sadece yeni incident_id'leri içeren zincirleri derin analiz et
                # Geçmiş zincirler zaten analiz edilmişti — duplikasyonu önler
        
            new_ids = set(incident_ids)
            for chain in chains:
                risk_icon = {"CRITICAL": "[C]", "HIGH": "[H]", "MEDIUM": "[M]", "LOW": "[L]"}.get(chain["chain_risk"], "[?]")
                entity = chain["entity"]
                tactics = " -> ".join(chain["tactics"])
                chain_ids = {inc.get("incident_id") for inc in chain.get("incidents", [])}
                has_new = bool(chain_ids & new_ids)
                if has_new and (chain["is_multistage"] or chain["chain_risk"] == "CRITICAL"):
                    analyze_chain_with_claude(chain)
                elif has_new:
                    print(f"\n  {risk_icon} {chain['chain_risk']:<8} {chain['chain_id']} | {chain['incident_count']} olay | {tactics}")
        
        # Email: yüksek riskli olaylar
            send_email_alert(escalate_events, ai_analyses)  # Sadece ESCALATE olaylar

            # Özet rapor — LOW/MEDIUM auto-log olayları
            if autolog_events:
                from collections import Counter
                tech_counts = Counter(e.get('detection_type', '?') for e in autolog_events)
                entities = set(f"{e.get('user','-')}@{e.get('host','-')}" for e in autolog_events)
                print(f"\n{'-'*65}")
                risk_dist = Counter(e.get('risk', '-') for e in autolog_events)
                risk_str = " | ".join(f"{r}x{c}" for r, c in sorted(risk_dist.items()))
                print(f"  [OZET] AUTO-LOG ÖZET ({len(autolog_events)} olay — {risk_str} — Claude'a gönderilmedi)")
                print(f"{'-'*65}")
                for tech, count in tech_counts.most_common():
                    print(f"  * {tech[:45]:<45} x{count}")
                print(f"  Etkilenen entity'ler: {', '.join(entities)}")
                print(f"  [i]  Manuel inceleme önerisi: Splunk'ta ilgili detection'ları kontrol et")
                print(f"{'-'*65}")
                # Pipeline özeti
                elapsed = round(time.time() - start_time, 1)
                escalated = len(all_events) - len(autolog_events)
                print(f"\n  [OK] Pipeline tamamlandı | {len(all_events)} detection | "
                      f"{escalated} ESCALATE | {len(autolog_events)} AUTO-LOG | "
                      f"{len(chains)} zincir | {len(incident_ids)} incident | {elapsed}s")
