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
    return_results=True → analiz metinlerini liste olarak döndürür (SOAR için)
    return_results=False → sadece ekrana yazdırır
    """
    if not events:
        print(f"\n{Colors.GRAY}  ℹ  Analiz edilecek olay bulunamadı.{Colors.RESET}")
        return []

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
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
Markdown formatting kullanma, düz metin yaz.
"""

        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        analysis_text = message.content[0].text

        # AI analiz çıktısı
        print(f"\n{Colors.BOLD}{Colors.CYAN}  AI DEĞERLENDİRMESİ{Colors.RESET}")
        print_divider(Colors.CYAN)
        for line in analysis_text.strip().split('\n'):
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
