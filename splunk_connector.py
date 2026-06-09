import splunklib.client as client
import splunklib.results as results
from dotenv import load_dotenv
import os
from datetime import datetime

load_dotenv()

def connect_splunk():
    """
    Splunk'a bağlantı kurar.
    8089 portu Splunk'un REST API portu, 8000 web arayüzünden farklı.
    """
    try:
        service = client.connect(
            host=os.getenv("SPLUNK_HOST"),
            port=int(os.getenv("SPLUNK_PORT")),
            username=os.getenv("SPLUNK_USERNAME"),
            password=os.getenv("SPLUNK_PASSWORD")
        )
        print(f"[+] Splunk bağlantısı başarılı — versiyon: {service.info['version']}")
        return service
    except Exception as e:
        print(f"[-] Splunk bağlantısı başarısız: {e}")
        return None

def load_query(query_file, threshold=5):
    """
    SPL sorgusunu harici .spl dosyasından okur.
    Dosyayı değiştirince Python'a dokunmana gerek kalmaz.
    """
    try:
        with open(query_file, "r") as f:
            query = f.read()
        # {threshold} ifadesini gerçek değerle değiştir
        query = query.replace("{threshold}", str(threshold))
        print(f"[+] Sorgu yüklendi: {query_file}")
        return query
    except FileNotFoundError:
        print(f"[-] Sorgu dosyası bulunamadı: {query_file}")
        return None

def _mv_last(value):
    """
    Splunk bazı field'ları çok-değerli (list) döndürür (örn. Account_Name).
    Bu helper, list ise boş olmayan son elemanı döndürür — mvindex(user,-1) pattern'iyle uyumlu.
    List değilse değeri olduğu gibi döndürür, boşsa '-' verir.
    """
    if isinstance(value, list):
        non_empty = [v for v in value if v not in ("", "-", None, "NOT_TRANSLATED")]
        return non_empty[-1] if non_empty else "-"
    return value if value not in ("", None) else "-"

def normalize_event(event):
    """
    Splunk'ın döndürdüğü farklı field adlarını ortak şemaya map eder.
    Örn: İngilizce Windows 'Account_Name' → 'user', 'ComputerName' → 'host'.
    Orijinal field'lar korunur, üzerine normalize edilmiş alias eklenir.
    Böylece downstream kod (ai_analyzer, soar_playbook) tek bir şema kullanır.
    """
    # Ortak şema → bu field aday listesinden ilk dolu olanı alır
    field_map = {
        "user":   ["Account_Name", "user", "TargetUserName", "Network_Account_Name", "User"],
        "domain": ["Account_Domain", "domain", "TargetDomainName", "Network_Account_Domain"],
        "host":   ["ComputerName", "host"],
        "src_ip": ["Source_Network_Address", "src_ip", "IpAddress"],
    }

    for norm_key, candidates in field_map.items():
        # Event'te zaten anlamlı bir değer varsa dokunma
        if event.get(norm_key) not in (None, "", "-"):
            continue
        # Aday field'ları sırayla dene
        found = False
        for cand in candidates:
            if cand in event:
                event[norm_key] = _mv_last(event[cand])
                found = True
                break
        # Hiçbiri yoksa '-' ata (downstream kod KeyError almasın)
        if not found:
            event[norm_key] = "-"
	# Sysmon User field'ı "DOMAIN\username" formatında gelebilir — sadece username al
        if event.get("user") and "\\" in str(event.get("user", "")):
            event["user"] = event["user"].split("\\")[-1]

    return event


def get_brute_force_events(service, threshold=5, query_file="queries/brute_force.spl"):
    """
    Brute force olaylarını Splunk'tan çeker.
    query_file: hangi SPL dosyasını kullanacağı
    threshold: kaç başarısız denemeden sonra şüpheli sayılsın
    """
    # Sorguyu dosyadan yükle
    spl_query = load_query(query_file, threshold)
    if not spl_query:
        return []

    try:
        # Sorguyu çalıştır, son 24 saate bak
        job = service.jobs.oneshot(
            spl_query,
            earliest_time="-24h",
            latest_time="now",
            output_mode="json"
        )

        # Sonuçları parse et
        reader = results.JSONResultsReader(job)
        events = []

        for result in reader:
            if isinstance(result, dict):
                events.append(result)

        print(f"[+] {len(events)} şüpheli olay bulundu")
        return events

    except Exception as e:
        print(f"[-] Sorgu hatası: {e}")
        return []

def print_events(events):
    """
    Olayları okunabilir formatta ekrana yazdırır.
    """
    if not events:
        print("[*] Şüpheli olay bulunamadı")
        return

    print("\n" + "="*60)
    print(f"BRUTE FORCE RAPORU — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    for event in events:
        risk = event.get('risk', 'UNKNOWN')
        user = event.get('user', '-')
        failures = event.get('failures', '0')
        successes = event.get('successes', '0')
        src_ip = event.get('src_ip', '-')
        host = event.get('host', '-')

        print(f"\n[{risk}] Kullanıcı: {user}")
        print(f"  Başarısız giriş : {failures}")
        print(f"  Başarılı giriş  : {successes}")
        print(f"  Kaynak IP       : {src_ip}")
        print(f"  Hedef makine    : {host}")

if __name__ == "__main__":
    service = connect_splunk()
    if service:
        events = get_brute_force_events(service, threshold=5)
        print_events(events)


def get_mitre_events(service, detection_name, spl_file, severity="HIGH", earliest="-5m"):
    """
    Herhangi bir MITRE ATT&CK detection kuralını çalıştırır.
    detection_name : alert adı (log ve AI analizi için)
    spl_file       : queries/sigma_converted/ altındaki .spl dosyası
    severity       : bu detection'ın risk seviyesi (CRITICAL/HIGH/MEDIUM)
    earliest       : ne kadar geriye bakılsın
    """
    spl_query = load_query(spl_file)
    if not spl_query:
        return []

    try:
        # Splunk API source= ile başlayan sorguları tanımıyor, search prefix gerekli
        if not spl_query.strip().startswith("search"):
            spl_query = "search " + spl_query

        job = service.jobs.oneshot(
            spl_query,
            earliest_time=earliest,
            latest_time="now",
            output_mode="json"
        )
        reader = results.JSONResultsReader(job)
        events = []
        for result in reader:
            if isinstance(result, dict):
                # Her event'e detection tipi ekle — AI analizi için gerekli
                result['detection_type'] = detection_name
                # Risk artık detection'a özgü severity'den geliyor (hardcode HIGH değil)
                result['risk'] = severity
                # Field adlarını ortak şemaya normalize et (Account_Name → user vb.)
                result = normalize_event(result)
                events.append(result)

        if events:
            print(f"[!] {detection_name}: {len(events)} olay bulundu")
        return events

    except Exception as e:
        print(f"[-] {detection_name} sorgu hatası: {e}")
        return []


def get_all_mitre_events(service, earliest="-5m"):
    """
    Tüm MITRE detection kurallarını çalıştırır, sonuçları birleştirir.
    Yeni kural eklemek için sadece bu listeye satır ekle.
    Her satır: (detection_name, spl_file, severity)
    """
    detections = [
        # (detection_name, spl_file, severity)
        ("T1550.002 Pass-the-Hash",
         "queries/sigma_converted/lateral_movement/T1550_pass_the_hash.spl", "CRITICAL"),
        ("T1070.001 Event Log Cleared",
         "queries/sigma_converted/defense_evasion/T1070_event_log_cleared.spl", "CRITICAL"),
        ("T1053.005 Suspicious Scheduled Task",
         "queries/sigma_converted/persistence/T1053_scheduled_task.spl", "HIGH"),
        ("T1078 External RDP Login",
         "queries/sigma_converted/initial_access/T1078_external_rdp_login.spl", "HIGH"),
        ("T1078 External SMB Login",
         "queries/sigma_converted/initial_access/T1078_external_smb_login.spl", "HIGH"),
        ("T1078 Suspicious Failed Logon Reasons",
         "queries/sigma_converted/initial_access/T1078_susp_failed_logon_reasons.spl", "MEDIUM"),
        ("T1078 Suspicious Failed Logon Source",
         "queries/sigma_converted/initial_access/T1078_susp_failed_logon_source.spl", "MEDIUM"),
        ("T1069 LDAP Recon",
         "queries/sigma_converted/discovery/T1069_ldap_recon.spl", "MEDIUM"),
        ("T1082 Network Recon",
         "queries/sigma_converted/discovery/T1082_net_recon.spl", "MEDIUM"),
        ("T1059 Obfuscation via MSHTA",
         "queries/sigma_converted/execution/T1059_obfuscation_mshta.spl", "HIGH"),
        ("T1059 Obfuscation via Rundll32",
         "queries/sigma_converted/execution/T1059_obfuscation_rundll32.spl", "HIGH"),
        ("T1059 Obfuscation via Stdin",
         "queries/sigma_converted/execution/T1059_obfuscation_stdin.spl", "HIGH"),
	# Faz 6 — DC gerektirmeyen ek teknikler (Sysmon)
        ("T1057 Process Discovery",
         "queries/sigma_converted/discovery/T1057_process_discovery.spl", "LOW"),
        ("T1083 File and Directory Discovery",
         "queries/sigma_converted/discovery/T1083_file_discovery.spl", "LOW"),
        ("T1012 Query Registry",
         "queries/sigma_converted/discovery/T1012_registry_query.spl", "LOW"),
        ("T1003.001 LSASS Memory Dump",
         "queries/sigma_converted/credential_access/T1003_lsass_dump.spl", "HIGH"),
        ("T1136.001 Create Local Account",
         "queries/sigma_converted/persistence/T1136_local_account.spl", "HIGH"),
        ("T1098 Account Manipulation",
         "queries/sigma_converted/persistence/T1098_account_manipulation.spl", "HIGH"),	
    ]

    all_events = []
    for detection_name, spl_file, severity in detections:
        events = get_mitre_events(service, detection_name, spl_file,
                                  severity=severity, earliest=earliest)
        all_events.extend(events)

    print(f"\n[+] Toplam {len(all_events)} MITRE event bulundu")
    return all_events
