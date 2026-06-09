import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv
import time
from incident_logger import log_incident_v2

load_dotenv()

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

    subject = f"[CRITICAL] SOC ALERT: {len(high_risk_pairs)} Yüksek Riskli Olay Tespit Edildi"
    
    body = f"""
SOC OTOMATİK UYARI SİSTEMİ
Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Toplam Yüksek Riskli Olay: {len(high_risk_pairs)}

{'='*60}
OLAY DETAYLARI
{'='*60}
"""
    
    for i, (event, analysis) in enumerate(high_risk_pairs):
        body += f"""
[{event.get('risk')}] OLAY #{i+1}
Kullanıcı    : {event.get('user', '-')}
Kaynak IP    : {event.get('src_ip', '-')}
Hedef Makine : {event.get('host', '-')}
Başarısız    : {event.get('failures', '0')}
Başarılı     : {event.get('successes', '0')}

AI ANALİZİ:
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
    from triage_scorer import triage_events, format_triage_summary

    start_time = time.time()
    service = connect_splunk()
    if service:
        # L1: Detection (Faz 1 + Faz 3)
        bf_events = get_brute_force_events(service, threshold=5)
        mitre_events = get_all_mitre_events(service, earliest=os.getenv("SEARCH_EARLIEST", "-5m"))
        all_events = bf_events + mitre_events

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
            triage = triage_events(all_events, chains=prelim_chains)
            print(format_triage_summary(triage))
            for i, (ev, sc) in enumerate(zip(all_events, triage["scores"]), 1):
                karar = {"ESCALATE": "-> L4-CLAUDE", "MONITOR": "-> IZLE", "SUPPRESS": "-> AUTO-LOG"}.get(sc["verdict"], sc["verdict"])
                # Skor bileşenlerini anlamlı açıklamaya çevir
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
                print(f"  #{i:<2} {ev.get('detection_type','?')[:35]:<35} | "
                      f"Skor:{sc['score']:3}/100 | "
                      f"{karar:<12} | {neden}")

            escalate_events = triage["escalate"]
            autolog_events = triage["autolog"]

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

            # Faz 5: Korelasyon — güncel incident geçmişiyle zincirleri çıkar
            try:
                with open("logs/incidents.json", "r", encoding="utf-8") as f:
                    all_incidents = json.load(f)
            except Exception:
                all_incidents = []
            chains = correlate_incidents(all_incidents, time_window_minutes=60)

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
            send_email_alert(combined_events, combined_analyses)

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
