import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv
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

    subject = f"🚨 SOC ALERT: {len(high_risk_pairs)} Yüksek Riskli Olay Tespit Edildi"
    
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

    service = connect_splunk()
    if service:
        # Brute force detection (Faz 1)
        bf_events = get_brute_force_events(service, threshold=5)
        # MITRE ATT&CK detection (Faz 3)
        mitre_events = get_all_mitre_events(service, earliest=os.getenv("SEARCH_EARLIEST", "-5m"))
        # Tüm eventleri birleştir
        all_events = bf_events + mitre_events

        if all_events:
            # Faz 3: Bireysel olay analizi
            ai_analyses = analyze_with_claude(all_events, return_results=True)

            # Faz 4: Structured incident logging + hash chain
            incident_ids = log_incident_v2(all_events, ai_analyses)

            # Faz 5: Korelasyon — olayları zincire grupla
            try:
                with open("logs/incidents.json", "r", encoding="utf-8") as f:
                    all_incidents = json.load(f)
            except Exception:
                all_incidents = []

            chains = correlate_incidents(all_incidents, time_window_minutes=60)

            if chains:
                print(f"\n{'='*65}")
                print(f"  🔗 KORİLASYON: {len(all_incidents)} olay → {len(chains)} kill-chain")
                print(f"{'='*65}")

                for chain in chains:
                    # Sadece çok aşamalı veya CRITICAL zincirleri derin analiz et
                    if chain["is_multistage"] or chain["chain_risk"] == "CRITICAL":
                        analyze_chain_with_claude(chain)
                    else:
                        # Tek olaylı/düşük riskli zincirleri sadece özetle
                        print(f"\n  [zincir] {format_chain_summary(chain)}")

            # Email: bireysel yüksek riskli olaylar
            send_email_alert(all_events, ai_analyses)

        else:
            print("\n  [*] Şüpheli olay bulunamadı")
