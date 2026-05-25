import anthropic
from dotenv import load_dotenv
import os

load_dotenv()

def analyze_with_claude(events, return_results=False):
    """
    Brute force olaylarını Claude Sonnet'e gönderir ve analiz ettirir.
    return_results=True → analiz metinlerini liste olarak döndürür (SOAR için)
    return_results=False → sadece ekrana yazdırır
    """
    if not events:
        print("[*] Analiz edilecek olay yok")
        return []

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    analyses = []
    # Tüm analizleri burada toplayacağız

    for event in events:
        user = event.get('user', '-')
        failures = event.get('failures', '0')
        successes = event.get('successes', '0')
        src_ip = event.get('src_ip', '-')
        host = event.get('host', '-')
        risk = event.get('risk', '-')
        domain = event.get('domain', '-')

        prompt = f"""
Sen bir SOC (Security Operations Center) analistisin. 
Aşağıdaki güvenlik olayını analiz et ve değerlendir:

OLAY BİLGİLERİ:
- Kullanıcı: {user}
- Domain: {domain}
- Hedef Makine: {host}
- Kaynak IP: {src_ip}
- Başarısız Giriş Sayısı: {failures}
- Başarılı Giriş Sayısı: {successes}
- Risk Seviyesi: {risk}

Lütfen şunları değerlendir:
1. Bu olay gerçek bir saldırı mı yoksa false positive mi olabilir?
2. Risk ne kadar ciddi?
3. SOC analisti ne yapmalı? (3 madde)
4. Bu bir iç tehdit mi dış tehdit mi?

Kısa ve net yanıt ver, maksimum 150 kelime.
"""

        print(f"\n{'='*60}")
        print(f"AI ANALİZİ — Kullanıcı: {user} | Risk: {risk}")
        print('='*60)

        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        analysis_text = message.content[0].text
        print(analysis_text)
        analyses.append(analysis_text)
        # Her analizi listeye ekle

    if return_results:
        return analyses
        # SOAR playbook'u analiz metinlerine ihtiyaç duyuyor
    
    return []

if __name__ == "__main__":
    from splunk_connector import connect_splunk, get_brute_force_events

    service = connect_splunk()
    if service:
        events = get_brute_force_events(service, threshold=5)
        analyze_with_claude(events)
