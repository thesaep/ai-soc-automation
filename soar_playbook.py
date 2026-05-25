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
    events: Splunk'tan gelen olay listesi
    ai_analyses: Claude'dan gelen analiz metinleri
    """
    # Sadece CRITICAL ve HIGH riskleri emaille bildir
    high_risk_events = [e for e in events if e.get('risk') in ['CRITICAL', 'HIGH']]
    
    if not high_risk_events:
        print("[*] Email gönderilmedi: CRITICAL/HIGH riskli olay yok")
        return

    # Email içeriğini oluştur
    subject = f"🚨 SOC ALERT: {len(high_risk_events)} Yüksek Riskli Olay Tespit Edildi"
    
    body = f"""
SOC OTOMATİK UYARI SİSTEMİ
Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Toplam Yüksek Riskli Olay: {len(high_risk_events)}

{'='*60}
OLAY DETAYLARI
{'='*60}
"""
    
    for i, event in enumerate(high_risk_events):
        analysis = ai_analyses[i] if i < len(ai_analyses) else "Analiz mevcut değil"
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

    # Email gönder
    try:
        msg = MIMEMultipart()
        msg['From'] = os.getenv("EMAIL_SENDER")
        msg['To'] = os.getenv("EMAIL_RECEIVER")
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain', 'utf-8'))

        # Gmail SMTP sunucusuna bağlan
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(
                os.getenv("EMAIL_SENDER"),
                os.getenv("EMAIL_PASSWORD")
            )
            server.send_message(msg)
        
        print(f"[+] Email gönderildi: {os.getenv('EMAIL_RECEIVER')}")
    
    except Exception as e:
        print(f"[-] Email gönderilemedi: {e}")

def log_incident(events, ai_analyses):
    """
    Olayları JSON formatında log dosyasına kaydeder.
    Her çalıştırmada yeni kayıt eklenir, eskiler silinmez.
    """
    log_file = "logs/incidents.json"
    os.makedirs("logs", exist_ok=True)
    # logs klasörü yoksa oluştur

    # Mevcut logları oku
    try:
        with open(log_file, "r") as f:
            existing_logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_logs = []
    # Dosya yoksa veya bozuksa boş liste ile başla

    # Yeni olayları ekle
    for i, event in enumerate(events):
        incident = {
            "timestamp": datetime.now().isoformat(),
            "user": event.get('user', '-'),
            "src_ip": event.get('src_ip', '-'),
            "host": event.get('host', '-'),
            "failures": event.get('failures', '0'),
            "successes": event.get('successes', '0'),
            "risk": event.get('risk', '-'),
            "ai_analysis": ai_analyses[i] if i < len(ai_analyses) else None
        }
        existing_logs.append(incident)

    # Güncel listeyi dosyaya yaz
    with open(log_file, "w") as f:
        json.dump(existing_logs, f, ensure_ascii=False, indent=2)
    # ensure_ascii=False → Türkçe karakterler bozulmasın
    # indent=2 → Okunabilir formatta kaydet

    print(f"[+] {len(events)} olay loglandı: {log_file}")

if __name__ == "__main__":
    from splunk_connector import connect_splunk, get_brute_force_events
    from ai_analyzer import analyze_with_claude

    service = connect_splunk()
    if service:
        events = get_brute_force_events(service, threshold=5)
        
        if events:
            # AI analizi yap ve sonuçları topla
            ai_analyses = analyze_with_claude(events, return_results=True)
            
            # Olayları logla
            log_incident(events, ai_analyses)
            
            # Yüksek riskli olaylar için email gönder
            send_email_alert(events, ai_analyses)
        else:
            print("[*] Şüpheli olay bulunamadı")
