from incident_logger import strip_anchors
from retro_hunt import retro_hunt
from case_manager import upsert_case
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

def send_email_alert(events, ai_analyses, trend_alerts=None):
    """
    Yüksek riskli olaylar için email bildirimi gönderir.
    Sadece CRITICAL ve HIGH risklerde tetiklenir.
    """
    # events ve ai_analyses paralel listeler, zip ile beraber filtrele
    high_risk_pairs = [
        (e, a) for e, a in zip(events, ai_analyses) 
        if e.get('risk') in ['CRITICAL', 'HIGH']
    ]
    
    # TREND varsa risk seviyesinden bağımsız gönder
    has_trend = bool(trend_alerts)
    if not high_risk_pairs and not has_trend:
        return
    # TREND varsa ama high_risk_pairs boşsa tüm escalate olayları ekle
    if not high_risk_pairs and has_trend:
        high_risk_pairs = list(zip(events, ai_analyses))

    risks = [e.get('risk', 'HIGH') for e, _ in high_risk_pairs]
    top_risk = 'CRITICAL' if 'CRITICAL' in risks else 'HIGH'
    subject = f"[{top_risk}] SOC ALERT: {len(high_risk_pairs)} High-Risk Events | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    body = f"""
SOC AUTOMATED ALERT SYSTEM
Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total    : {len(high_risk_pairs)} high-risk events
{'='*60}
EVENT DETAILS
{'='*60}
"""
    # TREND uyarıları varsa email'e ekle
    if trend_alerts:
        body += f"""
{'='*60}
⚠ TREND ALERTS
{'='*60}
"""
        for tk, mc in trend_alerts.items():
            detection, host = tk.split("|") if "|" in tk else (tk, "-")
            body += f"  * {detection} | {host} | {mc}x MONITOR - trend threshold exceeded\n"
        body += f"{'='*60}\n"

    for i, (event, analysis) in enumerate(high_risk_pairs):
        body += f"""
[{event.get('risk')}] EVENT #{i+1}
Detection    : {event.get('detection_type', '-')}
User         : {event.get('user', '-')}
Host         : {event.get('host', '-')}
Source IP    : {event.get('src_ip', '-')}
MITRE Tech   : {_get_technique_id(event.get('detection_type',''))}
AI ANALYSIS:
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
        print(f"\n  [-] Email failed to send: {e}")


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
        # L1 Throttle cache — incidents.json'dan bağımsız, hafif ayrı dosya
        _THROTTLE_FILE = "logs/throttle_cache.json"
        _throttle_keys = set()
        _now_t = _tdt.now(_ttz.utc)
        _t_cutoff = (_now_t - _ttd(minutes=5)).isoformat()
        try:
            with open(_THROTTLE_FILE, "r", encoding="utf-8") as _tf:
                _tcache = _tjson.load(_tf)
            # TTL dolmamış kayıtları throttle_keys'e ekle
            _tcache_clean = {k: v for k, v in _tcache.items() if v >= _t_cutoff}
            _throttle_keys = set(tuple(k.split("|")) for k in _tcache_clean)
        except Exception:
            _tcache_clean = {}
        _before = len(all_events)
        all_events = [
            e for e in all_events
            if (e.get("detection_type",""), e.get("user","-"), e.get("host","-")) not in _throttle_keys
        ]
        _throttled = _before - len(all_events)
        if _throttled > 0:
            print(f"  [THROTTLE] {_throttled} events already processed in last 5min - skipped")
        # Kalan olayları throttle cache'e yaz
        _now_str = _now_t.isoformat()
        for _e in all_events:
            _tk = "|".join([_e.get("detection_type",""), _e.get("user","-"), _e.get("host","-")])
            _tcache_clean[_tk] = _now_str
        try:
            import os as _os
            _os.makedirs("logs", exist_ok=True)
            with open(_THROTTLE_FILE, "w", encoding="utf-8") as _tf:
                _tjson.dump(_tcache_clean, _tf)
        except Exception:
            pass

        _trend_store = {}  # fix: "0 şüpheli olay" durumunda da tanımlı olsun (NameError önleme)
        escalate_events = []
        ai_analyses = []
        autolog_events = []
        if not all_events:
            print("\n  [*] No suspicious events found")
        else:
            # Korelasyon için önce mevcut incident geçmişini yükle (zincir üyeliği skoru etkiler)
            try:
                with open("logs/incidents.json", "r", encoding="utf-8") as f:
                    history = strip_anchors(json.load(f))
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
                    _all_inc = strip_anchors(_json.load(_f))
                from datetime import datetime as _dt, timezone as _tz, timedelta as _td
                _cutoff = (_dt.now(_tz.utc) - _td(days=7)).isoformat()
                for _inc in _all_inc:
                    if _inc.get("timestamp","") < _cutoff:
                        continue
                    if _inc.get("pipeline_trace",{}).get("triage_verdict") == "MONITOR":
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
                print(f"  [i] {len(duplicate_escalate)} duplicate events moved to AUTO-LOG "
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
            print(f"L2 TRIAGE: {_total} events evaluated")
            print(f"  -> ESCALATE (L4 Claude): {_esc_unique} events (+ {_esc_dup} duplicates moved to AUTO-LOG)")
            print(f"  -> AUTO-LOG (L2):        {_autolog} events")
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
                print(f"\n  -> {len(escalate_events)} events escalated to L4 (Claude) analysis")
                ai_analyses = analyze_with_claude(escalate_events, return_results=True)
                # Faz 8.5: AI analiz sonucunu ev["_enrichment"]["ai"]'a yaz
                for _ev, _analysis in zip(escalate_events, ai_analyses):
                    if "_enrichment" not in _ev:
                        _ev["_enrichment"] = {"ioc": {}, "ai": {}, "asset": {}}
                    _ev["_enrichment"]["ai"] = {"analysis": _analysis}
            else:
                print(f"\n  -> No events passed threshold, L4 skipped (token savings)")
                ai_analyses = []

            # Auto-log olanlar için Claude analizi yerine placeholder
            autolog_analyses = ["[L2 AUTO-LOG] Below score threshold, auto-logged, under monitoring."
                                for _ in autolog_events]

            # Tüm olayları logla (escalate + autolog), sırayı koru
            combined_events = escalate_events + autolog_events
            combined_analyses = ai_analyses + autolog_analyses
            # triage["scores"] all_events sırasıyla eşleşiyor
            # combined_events = escalate + autolog = all_events sırası korunuyor
            combined_scores = triage["scores"]
            # Faz 7 + 8.5: Artifact enrichment — log'dan ÖNCE, _enrichment["ioc"] dolsun
            print(f"\n  [ARTIFACT] IOC enrichment starting ({len(escalate_events)} ESCALATE events)...")
            _retro_cache = {}  # Faz 9.5 perf: ayni IOC bir kosuda bir kez retro-hunt
            for ev in escalate_events:
                # inc_id henüz yok — None ile çalış (seen_count + IOC pivot güncellenir)
                artifacts = process_event_artifacts(ev, None)
                # Faz 8.5: enrichment bloğu — orijinal ev alanlarına dokunmadan yan veri
                if "_enrichment" not in ev:
                    ev["_enrichment"] = {"ioc": {}, "ai": {}, "asset": {}}
                for art in artifacts:
                    ioc_val = art.get("value", "")
                    if ioc_val:
                        ev["_enrichment"]["ioc"][ioc_val] = {
                            "ioc_type":   art.get("ioc_type"),
                            "verdict":    art.get("enrichment", {}).get("verdict"),
                            "risk_score": art.get("enrichment", {}).get("risk_score"),
                            "sources":    art.get("enrichment", {}).get("sources", []),
                            "tags":       art.get("enrichment", {}).get("tags", []),
                        }
                        # Faz 9: Retro-hunt — enrichment malicious/suspicious verdiyse
                        # bu IOC gecmiste BASKA host'larda da gorundu mu? known_legitimate
                        # (Tailscale gibi) ve dusuk riskli gostergeler taranmaz (gurultu).
                        _v = ev["_enrichment"]["ioc"][ioc_val].get("verdict")
                        _it = art.get("ioc_type")
                        if _v in ("malicious", "suspicious") and _it:
                            try:
                                # Kosu-ici cache: ayni IOC iki olayda gecerse tek sorgu.
                                # Pencere -30d (yayilimin cogu bu araliktadir; -90d her
                                # cagrida arsiv buckets'i tariyordu, ~5s/sorgu).
                                _ck = f"{_it}:{ioc_val}"
                                if _ck in _retro_cache:
                                    _retro = _retro_cache[_ck]
                                else:
                                    _retro = retro_hunt(_it, ioc_val, earliest="-30d", service=service)
                                    _retro_cache[_ck] = _retro
                                if _retro.get("host_count", 0) >= 1:
                                    ev["_enrichment"]["ioc"][ioc_val]["retro"] = {
                                        "host_count": _retro["host_count"],
                                        "total_hits": _retro["total_hits"],
                                        "matches": _retro["matches"],
                                    }
                                    if _retro["host_count"] > 1:
                                        print(f"    [RETRO] {ioc_val} ({_v}) -> {_retro['host_count']} host, "
                                              f"{_retro['total_hits']} hit [YAYILIM]")
                                    else:
                                        print(f"    [RETRO] {ioc_val} ({_v}) -> tek host, "
                                              f"{_retro['total_hits']} hit")
                            except Exception as _e:
                                print(f"    [RETRO] hata: {_e}")
            incident_ids = log_incident_v2(combined_events, combined_analyses, triage_scores=combined_scores)
            # Faz 7: inc_id'yi artifact'a geri yaz (pivot için)
            for ev, inc_id in zip(escalate_events, incident_ids[:len(escalate_events)]):
                if inc_id:
                    process_event_artifacts(ev, inc_id)

            # Faz 5: Korelasyon — güncel incident geçmişiyle zincirleri çıkar
            try:
                with open("logs/incidents.json", "r", encoding="utf-8") as f:
                    all_incidents = strip_anchors(json.load(f))
            except Exception:
                all_incidents = []
            # Korelasyon için sadece son 7 günün incident'larını kullan — performans optimizasyonu
            from datetime import datetime, timezone, timedelta
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            recent_incidents = [i for i in all_incidents if i.get("timestamp", "") >= cutoff]
            chains = correlate_incidents(recent_incidents, time_window_minutes=240) # 4h — APT lateral movement kapsamı genişletildi (Faz 6 sonrası)

            if chains:
                print(f"\n{'='*65}")
                print(f"  [CHAIN] CORRELATION: {len(all_incidents)} events ({len(all_events)} new) -> {len(chains)} chains")
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
                _chain_ai = None
                if has_new and (chain["is_multistage"] or chain["chain_risk"] == "CRITICAL"):
                    _chain_ai = analyze_chain_with_claude(chain, return_result=True)
                elif has_new:
                    print(f"\n  {risk_icon} {chain['chain_risk']:<8} {chain['chain_id']} | {chain['incident_count']} events | {tactics}")
                # Faz 9.5: zinciri kalici Case'e cevir (idempotent — deterministik UID).
                # Her zincir icin cagrilir; ayni zincir kosudan kosuya ayni Case'e duser,
                # cogalmaz. AI analizi varsa Case'e baglanir.
                try:
                    _case = upsert_case(chain, ai_analysis=(_chain_ai if isinstance(_chain_ai, str) else None))
                    if has_new:
                        print(f"       [CASE] {_case['correlation_uid']} "
                              f"({_case['incident_count']} incident, seen x{_case['seen_count']})")
                except Exception as _ce:
                    print(f"       [CASE] hata: {_ce}")

            # MONITOR olayları için TREND uyarısı — ayrı dosyadan bağımsız sayaç
            import json as _tj
            _TREND_FILE = "logs/monitor_trend.json"
            try:
                with open(_TREND_FILE) as _tf:
                    _trend_store = _tj.load(_tf)
            except:
                _trend_store = {}
            monitor_events = triage.get("monitor", [])
            if monitor_events:
                print(f"\n{'-'*65}")
                print(f"  [MONITOR] {len(monitor_events)} events under monitoring")
                # TREND = "bu desen ZAMAN ICINDE tekrar ediyor" sinyali.
                # Ayni kosuda ayni desenden N olay gelmesi N tekrar DEGILDIR,
                # tek bir gozlemdir; sayac kosu basina desen basina 1 artar.
                # Aksi halde tek gurultulu kosu esigi (3x) aninda asar.
                _trend_seen = set()
                for ev in monitor_events:
                    # Key: (detection, host) — user boş olabilir, host sabit
                    _tk = f"{ev.get('detection_type','')}|{ev.get('host','-')}"
                    if _tk not in _trend_seen:
                        _trend_seen.add(_tk)
                        _trend_store[_tk] = _trend_store.get(_tk, 0) + 1
                    mc = _trend_store[_tk]
                    trend_str = f" ⚠ TREND ({mc}x MONITOR)" if mc >= 3 else f" ({mc}x)"
                    # AI'a trend context'i ver — eşik aşıldıysa event'e ekle
                    if mc >= 3:
                        ev["_trend_info"] = f"This event has repeated {mc} times at MONITOR level and exceeded the trend threshold ({3}x), so it was escalated for analysis. Assess it in the context of a recurring pattern."
                    # Ayni detection'dan birden fazla olay ayni satir gorunumune
                    # duser (ornek: iki farkli tasklist cagrisi). Olay saati
                    # ayirt edicidir ve idempotency anahtarinin da parcasidir,
                    # yani ekranda gorulen deger sistemin kullandigi kriterle ayni.
                    _et = str(ev.get('event_time', '') or '')
                    _ets = f" | {_et[11:19]}" if len(_et) >= 19 else ""
                    print(f"  * {ev.get('detection_type','')[:40]:<40} | {ev.get('user','-')} | score:{ev.get('_triage',{}).get('score',0)}{trend_str}{_ets}")
                # Trend store'u kaydet
                try:
                    with open(_TREND_FILE, "w") as _tf:
                        _tj.dump(_trend_store, _tf)
                except:
                    pass

        # Email: yüksek riskli olaylar + TREND uyarıları
        _trend_alerts = {k: v for k, v in _trend_store.items() if v >= 3} if _trend_store else {}
        send_email_alert(escalate_events, ai_analyses, trend_alerts=_trend_alerts if _trend_alerts else None)

        # Özet rapor — LOW/MEDIUM auto-log olayları
        if autolog_events:
            from collections import Counter
            tech_counts = Counter(e.get('detection_type', '?') for e in autolog_events)
            entities = set(f"{e.get('user','-')}@{e.get('host','-')}" for e in autolog_events)
            print(f"\n{'-'*65}")
            risk_dist = Counter(e.get('risk', '-') for e in autolog_events)
            risk_str = " | ".join(f"{r}x{c}" for r, c in sorted(risk_dist.items()))
            print(f"  [SUMMARY] AUTO-LOG SUMMARY ({len(autolog_events)} events - {risk_str} - not sent to Claude)")
            print(f"{'-'*65}")
            for tech, count in tech_counts.most_common():
                print(f"  * {tech[:45]:<45} x{count}")
            print(f"  Affected entities: {', '.join(entities)}")
            print(f"  [i]  Manual review suggestion: check related detections in Splunk")
            print(f"{'-'*65}")
            # Pipeline özeti
            elapsed = round(time.time() - start_time, 1)
            escalated = len(all_events) - len(autolog_events)
            print(f"\n  [OK] Pipeline completed | {len(all_events)} detection | "
                  f"{escalated} ESCALATE | {len(autolog_events)} AUTO-LOG | "
                  f"{len(chains)} chains | {len(incident_ids)} incidents | {elapsed}s")
            # L3 indeks otomatik yenile — yeni incident loglandıysa ChromaDB güncelle
            # Elle çalıştırmaya gerek kalmasın; boş pipeline'da (0 incident) atla
            if incident_ids:
                try:
                    import semantic_retriever as _sr_idx
                    _sr_idx.index_incidents()
                    print(f"  [L3] Semantic index refreshed ({_sr_idx.INCIDENTS_PATH})")
                except Exception as _e:
                    print(f"  [L3] Index refresh skipped: {_e}")
