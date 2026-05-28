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


def get_mitre_events(service, detection_name, spl_file, earliest="-5m"):
    """
    Herhangi bir MITRE ATT&CK detection kuralını çalıştırır.
    detection_name : alert adı (log ve AI analizi için)
    spl_file       : queries/sigma_converted/ altındaki .spl dosyası
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
                result['risk'] = result.get('risk', 'HIGH')
                events.append(result)

        if events:
            print(f"[!] {detection_name}: {len(events)} olay bulundu")
        return events

    except Exception as e:
        print(f"[-] {detection_name} sorgu hatası: {e}")
        return []


def get_all_mitre_events(service):
    """
    Tüm MITRE detection kurallarını çalıştırır, sonuçları birleştirir.
    Yeni kural eklemek için sadece bu listeye satır ekle.
    """
    detections = [
        # (detection_name, spl_file)
        ("T1550.002 Pass-the-Hash",
         "queries/sigma_converted/lateral_movement/T1550_pass_the_hash.spl"),
        ("T1070.001 Event Log Cleared",
         "queries/sigma_converted/defense_evasion/T1070_event_log_cleared.spl"),
        ("T1053.005 Suspicious Scheduled Task",
         "queries/sigma_converted/persistence/T1053_scheduled_task.spl"),
        ("T1078 External RDP Login",
         "queries/sigma_converted/initial_access/T1078_external_rdp_login.spl"),
        ("T1078 External SMB Login",
         "queries/sigma_converted/initial_access/T1078_external_smb_login.spl"),
        ("T1078 Suspicious Failed Logon Reasons",
         "queries/sigma_converted/initial_access/T1078_susp_failed_logon_reasons.spl"),
        ("T1078 Suspicious Failed Logon Source",
         "queries/sigma_converted/initial_access/T1078_susp_failed_logon_source.spl"),
        ("T1069 LDAP Recon",
         "queries/sigma_converted/discovery/T1069_ldap_recon.spl"),
        ("T1082 Network Recon",
         "queries/sigma_converted/discovery/T1082_net_recon.spl"),
        ("T1059 Obfuscation via MSHTA",
         "queries/sigma_converted/execution/T1059_obfuscation_mshta.spl"),
        ("T1059 Obfuscation via Rundll32",
         "queries/sigma_converted/execution/T1059_obfuscation_rundll32.spl"),
        ("T1059 Obfuscation via Stdin",
         "queries/sigma_converted/execution/T1059_obfuscation_stdin.spl"),
    ]

    all_events = []
    for detection_name, spl_file in detections:
        events = get_mitre_events(service, detection_name, spl_file)
        all_events.extend(events)

    print(f"\n[+] Toplam {len(all_events)} MITRE event bulundu")
    return all_events
