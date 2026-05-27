import anthropic
from dotenv import load_dotenv
import os

load_dotenv()

# Terminal renk kodları
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_DARK = "\033[40m"

def risk_color(risk):
    """Risk seviyesine göre renk döndürür."""
    colors = {
        "CRITICAL": Colors.BG_RED + Colors.WHITE + Colors.BOLD,
        "HIGH":     Colors.RED + Colors.BOLD,
        "MEDIUM":   Colors.YELLOW + Colors.BOLD,
        "LOW":      Colors.GREEN + Colors.BOLD,
    }
    return colors.get(risk, Colors.WHITE)

def print_header(text, color=Colors.CYAN):
    width = 65
    print(f"\n{color}{Colors.BOLD}{'═' * width}{Colors.RESET}")
    print(f"{color}{Colors.BOLD}  {text}{Colors.RESET}")
    print(f"{color}{Colors.BOLD}{'═' * width}{Colors.RESET}")

def print_divider(color=Colors.GRAY):
    print(f"{color}{'─' * 65}{Colors.RESET}")

def print_field(label, value, label_color=Colors.CYAN, value_color=Colors.WHITE):
    print(f"  {label_color}{Colors.BOLD}{label:<20}{Colors.RESET}{value_color}{value}{Colors.RESET}")

def analyze_with_claude(events, return_results=False):
    """
    Brute force olaylarını Claude Sonnet'e gönderir ve analiz ettirir.
    Tüm eventleri TEK API çağrısında batch olarak işler (token tasarrufu).
    return_results=True → analiz metinlerini liste olarak döndürür (SOAR için)
    return_results=False → sadece ekrana yazdırır
    """
    if not events:
        print(f"\n{Colors.GRAY}  ℹ  Analiz edilecek olay bulunamadı.{Colors.RESET}")
        return []

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    # Tüm eventleri tek prompt'a birleştir
    event_blocks = []
    for i, event in enumerate(events):
        block = f"""OLAY #{i+1}:
- Kullanıcı: {event.get('user', '-')}
- Domain: {event.get('domain', '-')}
- Hedef Makine: {event.get('host', '-')}
- Kaynak IP: {event.get('src_ip', '-')}
- Başarısız Giriş Sayısı: {event.get('failures', '0')}
- Başarılı Giriş Sayısı: {event.get('successes', '0')}
- Risk Seviyesi: {event.get('risk', '-')}"""
        event_blocks.append(block)

    combined_events = "\n\n".join(event_blocks)

    # Ara başlıklı, yapılandırılmış format
    prompt = f"""Sen bir SOC (Security Operations Center) analistisin.
Aşağıdaki {len(events)} güvenlik olayını analiz et ve değerlendir:

{combined_events}

HER OLAY İÇİN ŞU FORMATTA YANIT VER:

OLAY #N:
SOC ANALİZ RAPORU

1. SALDIRI MI / FALSE POSITIVE MI?
(Tek paragraf cevap, 2-3 cümle)

2. RİSK CİDDİYETİ:
(Tek paragraf cevap, 2-3 cümle)

3. SOC ANALİSTİ NE YAPMALI:
- (1. eylem önerisi)
- (2. eylem önerisi)
- (3. eylem önerisi)

4. İÇ Mİ DIŞ TEHDİT?
(Tek paragraf cevap, 2-3 cümle)

KURALLAR:
- Her olay "OLAY #N:" satırıyla başlamalı, sonra yukarıdaki formatta devam etmeli.
- Markdown formatting (yıldız, tire) KULLANMA, düz metin yaz.
- Her madde kısa ve net olsun.

Şimdi {len(events)} olay için bu formatta yanıt ver."""

    
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=8000,   # 10 event için fazlasıyla yeterli, maliyet sadece kullanılan token'dan çıkar
        messages=[{"role": "user", "content": prompt}]
    )


    raw_response = message.content[0].text

    # Response'u "OLAY #N:" başlıklarına göre böl
    import re
    parts = re.split(r'OLAY\s*#\d+\s*:?\s*', raw_response.strip())
    parts = [p.strip() for p in parts if p.strip()]

    # Parse başarısızsa fallback
    if len(parts) != len(events):
        print(f"\n{Colors.YELLOW}  ⚠  Parse uyarısı: {len(events)} olay beklendi, "
              f"{len(parts)} parça bulundu.{Colors.RESET}")
        # Eksik parçaları boş string ile tamamla
        while len(parts) < len(events):
            parts.append("Analiz alınamadı.")

    analyses = []

    for i, event in enumerate(events):
        user      = event.get('user', '-')
        failures  = event.get('failures', '0')
        successes = event.get('successes', '0')
        src_ip    = event.get('src_ip', '-')
        host      = event.get('host', '-')
        risk      = event.get('risk', '-')
        domain    = event.get('domain', '-')

        rc = risk_color(risk)

        # Olay başlığı
        print_header(f"AI ANALİZİ  #{i+1}  |  Kullanıcı: {user}  |  Risk: {risk}", rc)

        # Olay detayları
        print(f"\n{Colors.BOLD}{Colors.BLUE}  OLAY BİLGİLERİ{Colors.RESET}")
        print_divider(Colors.BLUE)
        print_field("Kullanıcı     :", user)
        print_field("Domain        :", domain)
        print_field("Hedef Makine  :", host)
        print_field("Kaynak IP     :", src_ip)
        print_field("Başarısız Giriş:", failures, value_color=Colors.RED)
        print_field("Başarılı Giriş :", successes, value_color=Colors.GREEN)
        print_field("Risk Seviyesi  :", f"{rc}{risk}{Colors.RESET}")

        # AI analiz çıktısı — i'inci event'in analizini al
        analysis_text = parts[i] if i < len(parts) else "Analiz alınamadı."

        print(f"\n{Colors.BOLD}{Colors.CYAN}  AI DEĞERLENDİRMESİ{Colors.RESET}")
        print_divider(Colors.CYAN)
        for line in analysis_text.split('\n'):
            print(f"  {Colors.WHITE}{line}{Colors.RESET}")

        # Risk bazlı aksiyon mesajı
        print()
        if risk == "CRITICAL":
            print(f"  {Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}  🚨 CRITICAL — Email bildirimi gönderildi, olay loglandı  {Colors.RESET}")
        elif risk == "HIGH":
            print(f"  {Colors.RED}{Colors.BOLD}  ⚠️  HIGH — Email bildirimi gönderildi, olay loglandı{Colors.RESET}")
        elif risk == "MEDIUM":
            print(f"  {Colors.YELLOW}{Colors.BOLD}  🔶 MEDIUM — Olay loglandı, izlemeye devam{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}{Colors.BOLD}  ✅ LOW — Olay loglandı{Colors.RESET}")

        analyses.append(analysis_text)

    return analyses if return_results else []


if __name__ == "__main__":
    from splunk_connector import connect_splunk, get_brute_force_events

    service = connect_splunk()
    if service:
        events = get_brute_force_events(service, threshold=5)
        analyze_with_claude(events)
