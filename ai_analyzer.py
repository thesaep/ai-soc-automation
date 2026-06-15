import json as _json

def get_mitre_context(detection_type):
    """
    detection_type string'inden MITRE teknik ID'sini çıkarır,
    mitre_context.json'dan açıklama getirir.
    """
    try:
        with open('mitre_context.json', 'r') as f:
            ctx = _json.load(f)
    except:
        return ""

    # detection_type içinde teknik ID ara
    for key in ctx:
        if key.lower() in detection_type.lower():
            t = ctx[key]
            return f"""
MITRE ATT&CK CONTEXT:
- Technique: {t['name']} ({key})
- Tactic: {t['tactic']}
- Description: {t['description']}
- Recommended Response: {t['response']}"""

    # brute force için fallback
    if 'brute' in detection_type.lower() or 'force' not in detection_type.lower():
        t = ctx.get('brute_force', {})
        if t:
            return f"""
MITRE ATT&CK CONTEXT:
- Technique: {t['name']}
- Tactic: {t['tactic']}
- Description: {t['description']}"""
    return ""


def _format_event_fields(event):
    """
    Event dict'inden Claude'a gönderilecek olay bilgilerini üretir.
    Normalize edilmiş field'ları (user, host, src_ip, domain) kullanır,
    ayrıca detection tipine özgü ham field'ları da ekler.
    Claude'un daha fazla context görmesi için tüm anlamlı field'lar eklenir.
    Splunk internal field'ları (_raw, _bkt vb.) ve Message (çok uzun) filtrelenir.
    """
    # Splunk internal ve gürültülü field'lar — prompt'a ekleme
    skip_fields = {
        '_raw', '_bkt', '_cd', '_indextime', '_pre_msg', '_serial',
        '_si', '_sourcetype', '_subsecond', '_time', 'linecount',
        'punct', 'splunk_server', 'splunk_server_group', 'index',
        'sourcetype', 'source', 'eventtype', 'Message'
    }

    lines = []
    # Normalize field'lar önce gelsin — en önemli bilgiler
    priority = ['detection_type', 'risk', 'user', 'domain', 'host', 'src_ip']
    for f in priority:
        v = event.get(f)
        if v and v != '-':
            lines.append(f"- {f}: {v}")

    # Kalan ham field'lar — detection'a özgü detaylar
    for k, v in event.items():
        if k in skip_fields or k in priority:
            continue
        if not k.startswith('_') and v not in (None, '', '-', [], '0'):
            # List ise join et
            if isinstance(v, list):
                v = ', '.join(str(x) for x in v if x not in ('', '-', None))
                if not v:
                    continue
            lines.append(f"- {k}: {v}")

    return "\n".join(lines)


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
    print(f"\n{color}{Colors.BOLD}{'=' * width}{Colors.RESET}")
    print(f"{color}{Colors.BOLD}  {text}{Colors.RESET}")
    print(f"{color}{Colors.BOLD}{'=' * width}{Colors.RESET}")

def print_divider(color=Colors.GRAY):
    print(f"{color}{'-' * 65}{Colors.RESET}")

def print_field(label, value, label_color=Colors.CYAN, value_color=Colors.WHITE):
    print(f"  {label_color}{Colors.BOLD}{label:<20}{Colors.RESET}{value_color}{value}{Colors.RESET}")

def analyze_with_claude(events, return_results=False):
    """
    Güvenlik olaylarını Claude Sonnet'e gönderir ve analiz ettirir.
    Tüm eventleri TEK API çağrısında batch olarak işler (token tasarrufu).
    Her event için normalize edilmiş + ham field'lar prompt'a eklenir.
    return_results=True -> analiz metinlerini liste olarak döndürür (SOAR için)
    return_results=False -> sadece ekrana yazdırır
    """
    if not events:
        print(f"\n{Colors.GRAY}  ℹ  Analiz edilecek olay bulunamadı.{Colors.RESET}")
        return []

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    # Tüm eventleri tek prompt'a birleştir
    # Her event için normalize + ham field'lar eklenir, Claude daha fazla context görür
    event_blocks = []
    for i, event in enumerate(events):
        fields = _format_event_fields(event)
        block = f"OLAY #{i+1}:\n{fields}"
        event_blocks.append(block)

    combined_events = "\n\n".join(event_blocks)

    # Her event'in detection_type'ından MITRE context çek
    mitre_contexts = []
    for event in events:
        dt = event.get('detection_type', 'brute_force')
        ctx = get_mitre_context(dt)
        if ctx and ctx not in mitre_contexts:
            mitre_contexts.append(ctx)
    mitre_section = "\n".join(mitre_contexts) if mitre_contexts else ""

    # Yapılandırılmış prompt — MITRE context + tüm event field'ları Claude'a gider
    prompt = f"""Sen bir SOC (Security Operations Center) analistisin.
Aşağıdaki {len(events)} güvenlik olayını analiz et ve değerlendir:
{mitre_section}

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
- Olay field'larındaki gerçek değerleri (kullanıcı adı, IP, makine adı vb.) analizde kullan.

Şimdi {len(events)} olay için bu formatta yanıt ver."""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=max(1000, len(events) * 600),
        messages=[{"role": "user", "content": prompt}]
    )

    raw_response = message.content[0].text

    # Response'u "OLAY #N:" başlıklarına göre böl
    import re
    parts = re.split(r'(?m)^OLAY\s*#\d+\s*:?\s*', raw_response.strip())
    parts = [p.strip() for p in parts if p.strip()]

    # Parse başarısızsa fallback
    if len(parts) != len(events):
        print(f"\n{Colors.YELLOW}  ⚠  Parse uyarısı: {len(events)} olay beklendi, "
              f"{len(parts)} parça bulundu.{Colors.RESET}")
        while len(parts) < len(events):
            parts.append("Analiz alınamadı.")

    analyses = []

    for i, event in enumerate(events):
        # Normalize field'lardan al — boşsa ham field'lara bak
        user      = event.get('user', '-')
        src_ip    = event.get('src_ip', '-')
        host      = event.get('host', '-')
        risk      = event.get('risk', '-')
        domain    = event.get('domain', '-')
        det_type  = event.get('detection_type', '-')
        # Brute force'a özgü field'lar (MITRE eventlerde olmayabilir, '-' döner)
        failures  = event.get('failures', '-')
        successes = event.get('successes', '-')

        rc = risk_color(risk)

        # Olay başlığı — detection tipi + kullanıcı + risk
        print_header(
            f"AI ANALİZİ  #{i+1}  |  {det_type}  |  Risk: {risk}", rc
        )

        # Olay detayları
        print(f"\n{Colors.BOLD}{Colors.BLUE}  OLAY BİLGİLERİ{Colors.RESET}")
        print_divider(Colors.BLUE)
        print_field("Detection     :", det_type)
        print_field("Kullanıcı     :", user)
        print_field("Domain        :", domain)
        print_field("Hedef Makine  :", host)
        print_field("Kaynak IP     :", src_ip)
        # Brute force field'ları varsa göster
        if failures != '-':
            print_field("Başarısız Giriş:", failures, value_color=Colors.RED)
        if successes != '-':
            print_field("Başarılı Giriş :", successes, value_color=Colors.GREEN)
        print_field("Risk Seviyesi  :", f"{rc}{risk}{Colors.RESET}")

        # AI analiz çıktısı
        analysis_text = parts[i] if i < len(parts) else "Analiz alınamadı."

        print(f"\n{Colors.BOLD}{Colors.CYAN}  AI DEĞERLENDİRMESİ{Colors.RESET}")
        print_divider(Colors.CYAN)
        for line in analysis_text.split('\n'):
            print(f"  {Colors.WHITE}{line}{Colors.RESET}")

        # Risk bazlı aksiyon mesajı
        print()
        if risk == "CRITICAL":
            print(f"  {Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}  [CRITICAL] CRITICAL — Email bildirimi gönderildi, olay loglandı  {Colors.RESET}")
        elif risk == "HIGH":
            print(f"  {Colors.RED}{Colors.BOLD}  [HIGH]  HIGH — Email bildirimi gönderildi, olay loglandı{Colors.RESET}")
        elif risk == "MEDIUM":
            print(f"  {Colors.YELLOW}{Colors.BOLD}  [MEDIUM] MEDIUM — Olay loglandı, izlemeye devam{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}{Colors.BOLD}  [OK] LOW — Olay loglandı{Colors.RESET}")

        analyses.append(analysis_text)

    return analyses if return_results else []

def analyze_chain_with_claude(chain: dict, return_result: bool = False):
    """
    Bir kill-chain zincirini bütün olarak Claude'a analiz ettirir.
    Tek tek olay analizi yerine saldırı kampanyasının bütününü değerlendirir.

    chain          : correlator.correlate_incidents() çıktısından bir zincir
    return_result  : True ise analiz metnini döndürür (soar_playbook için)
    """
    import anthropic
    import os
    from dotenv import load_dotenv
    load_dotenv()

    incidents = chain.get("incidents", [])
    if not incidents:
        return ""

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    # Zincirdeki her olayı prompt'a ekle
    incident_blocks = []
    for i, inc in enumerate(incidents, 1):
        entity  = inc.get("entity", {})
        mitre   = inc.get("mitre", {})
        trace   = inc.get("pipeline_trace", {})
        fields  = trace.get("triggered_fields", {})

        block = f"""OLAY #{i}:
- Detection   : {mitre.get('technique_name', '-')}
- Teknik ID   : {mitre.get('technique_id', '-')}
- Taktik      : {mitre.get('tactic', '-')}
- Risk        : {inc.get('risk', '-')}
- Kullanıcı   : {entity.get('user', '-')}
- Makine      : {entity.get('host', '-')}
- Kaynak IP   : {entity.get('src_ip', '-')}
- Kanıt field'ları: {fields}"""
        incident_blocks.append(block)

    combined = "\n\n".join(incident_blocks)

    # Kill-chain özeti
    tactics_str   = " -> ".join(chain.get("tactics", []))
    techniques_str = ", ".join(chain.get("techniques", []))
    chain_risk    = chain.get("chain_risk", "-")
    is_multistage = chain.get("is_multistage", False)
    time_span     = chain.get("time_span_minutes", 0)

    prompt = f"""Sen deneyimli bir SOC analistisin. Aşağıdaki {len(incidents)} güvenlik olayı,
aynı kullanıcı ve makine üzerinde kısa sürede gerçekleşmiş ve otomatik korelasyon sistemi
tarafından tek bir saldırı kampanyasına ait olarak gruplandırılmıştır.

ZINCIR ÖZETI:
- Hedef: {chain['entity']['user']} @ {chain['entity']['host']}
- Zincir riski: {chain_risk}
- Zaman aralığı: {time_span} dakika
- Kill-chain aşamaları: {tactics_str}
- Tespit edilen teknikler: {techniques_str}
- Çok aşamalı saldırı: {"Evet" if is_multistage else "Hayır"}

OLAYLAR:
{combined}

Bu zinciri bir bütün olarak değerlendir ve şu formatta yanıt ver:

KİLL-CHAIN ANALİZİ:

1. SALDIRI KAMPANYASI DEĞERLENDİRMESİ:
(Bu olaylar gerçek bir koordineli saldırıyı mı temsil ediyor? 2-3 cümle)

2. SALDIRGANIN AMACI:
(Mevcut kill-chain aşamalarına göre saldırganın nihai hedefi ne? 2-3 cümle)

3. SALDIRININ HANGİ AŞAMASINDAYIZ:
(Kill-chain'de neredeyiz, hangi aşamalar tamamlandı, hangisi muhtemelen sırada? 2-3 cümle)

4. SONRAKI MUHTEMEL ADIM:
(Saldırganın büyük ihtimalle sonraki hamlesi ne olacak? Somut teknik tahmin yap)

5. ACİL AKSİYONLAR:
- (En kritik 1. eylem)
- (En kritik 2. eylem)
- (En kritik 3. eylem)

KURALLAR:
- Olayları birbirine bağla, izole değerlendir.
- Teknik ATT&CK terminolojisini kullan.
- Markdown formatting kullanma, düz metin yaz.
"""

    rc = risk_color(chain_risk)
    print_header(
        f"[CHAIN] KİLL-CHAIN ANALİZİ  |  {chain['entity']['user']} @ {chain['entity']['host']}  |  {chain_risk}",
        rc
    )
    print(f"\n{Colors.BOLD}{Colors.BLUE}  ZİNCİR BİLGİLERİ{Colors.RESET}")
    print_divider(Colors.BLUE)
    print_field("Zincir ID     :", chain.get("chain_id", "-"))
    print_field("Olay Sayısı   :", str(len(incidents)))
    print_field("Zincir Riski  :", f"{rc}{chain_risk}{Colors.RESET}")
    print_field("Zaman Aralığı :", f"{time_span} dakika")
    print_field("Kill-Chain    :", tactics_str)
    print_field("Teknikler     :", techniques_str)

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        analysis = message.content[0].text

        print(f"\n{Colors.BOLD}{Colors.CYAN}  KAMPANYA ANALİZİ{Colors.RESET}")
        print_divider(Colors.CYAN)
        for line in analysis.split("\n"):
            print(f"  {Colors.WHITE}{line}{Colors.RESET}")

        print()
        if chain_risk == "CRITICAL":
            print(f"  {Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}  [CRITICAL] KRİTİK KAMPANYA — Koordineli saldırı tespit edildi  {Colors.RESET}")
        elif chain_risk == "HIGH":
            print(f"  {Colors.RED}{Colors.BOLD}  [HIGH]  YÜKSEK RİSKLİ KAMPANYA — Derhal müdahale gerekiyor{Colors.RESET}")

        if return_result:
            return analysis
        return ""

    except Exception as e:
        print(f"[-] Chain analiz hatası: {e}")
        return ""

if __name__ == "__main__":
    from splunk_connector import connect_splunk, get_brute_force_events

    service = connect_splunk()
    if service:
        events = get_brute_force_events(service, threshold=5)
        analyze_with_claude(events)
