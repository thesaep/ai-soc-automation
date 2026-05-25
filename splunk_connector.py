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
