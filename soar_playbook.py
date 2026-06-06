import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv

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

def log_incident(events, ai_analyses):
    """
    Olayları JSON formatında log dosyasına kaydeder.
    """
    log_file = "logs/incidents.json"
    os.makedirs("logs", exist_ok=True)

    try:
        with open(log_file, "r") as f:
            existing_logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_logs = []

    for event, analysis in zip(events, ai_analyses):
        incident = {
            "timestamp": datetime.now().isoformat(),
            "user": event.get('user', '-'),
            "src_ip": event.get('src_ip', '-'),
            "host": event.get('host', '-'),
            "failures": event.get('failures', '0'),
            "successes": event.get('successes', '0'),
            "risk": event.get('risk', '-'),
            "ai_analysis": analysis
        }
        existing_logs.append(incident)

    with open(log_file, "w") as f:
        json.dump(existing_logs, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    from splunk_connector import connect_splunk, get_brute_force_events, get_all_mitre_events
    from ai_analyzer import analyze_with_claude

    service = connect_splunk()
    if service:
        # Brute force detection (Faz 1)
        bf_events = get_brute_force_events(service, threshold=5)

        # MITRE ATT&CK detection (Faz 3)
        mitre_events = get_all_mitre_events(service, earliest=os.getenv("SEARCH_EARLIEST", "-5m"))

        # Tüm eventleri birleştir
        all_events = bf_events + mitre_events

        if all_events:
            ai_analyses = analyze_with_claude(all_events, return_results=True)
            log_incident(all_events, ai_analyses)
            send_email_alert(all_events, ai_analyses)
        else:
            print("\n  [*] Şüpheli olay bulunamadı")
