import os
import requests
import urllib3
from dotenv import load_dotenv

# .env dosyasından değişkenleri yükle
load_dotenv()

urllib3.disable_warnings()

# Credentials .env'den okunuyor, koda yazılmıyor
SPLUNK_URL = os.getenv("SPLUNK_URL", "https://localhost:8089")
AUTH = (os.getenv("SPLUNK_USERNAME"), os.getenv("SPLUNK_PASSWORD"))

alerts = [
    {
        "name": "MITRE T1070 - Event Log Cleared",
        "file": "defense_evasion/T1070_event_log_cleared.spl",
        "severity": "critical",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1069 - LDAP Recon",
        "file": "discovery/T1069_ldap_recon.spl",
        "severity": "medium",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1082 - Network Recon",
        "file": "discovery/T1082_net_recon.spl",
        "severity": "medium",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1059 - Obfuscation via MSHTA",
        "file": "execution/T1059_obfuscation_mshta.spl",
        "severity": "high",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1059 - Obfuscation via Rundll32",
        "file": "execution/T1059_obfuscation_rundll32.spl",
        "severity": "high",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1059 - Obfuscation via Stdin",
        "file": "execution/T1059_obfuscation_stdin.spl",
        "severity": "high",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1078 - External RDP Login",
        "file": "initial_access/T1078_external_rdp_login.spl",
        "severity": "high",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1078 - External SMB Login",
        "file": "initial_access/T1078_external_smb_login.spl",
        "severity": "high",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1078 - Suspicious Failed Logon Reasons",
        "file": "initial_access/T1078_susp_failed_logon_reasons.spl",
        "severity": "medium",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1078 - Suspicious Failed Logon Source",
        "file": "initial_access/T1078_susp_failed_logon_source.spl",
        "severity": "medium",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1550 - Pass the Hash",
        "file": "lateral_movement/T1550_pass_the_hash.spl",
        "severity": "critical",
        "cron": "*/5 * * * *"
    },
    {
        "name": "MITRE T1053 - Suspicious Scheduled Task",
        "file": "persistence/T1053_scheduled_task.spl",
        "severity": "high",
        "cron": "*/5 * * * *"
    },
]

# SPL dosyalarının bulunduğu dizin
base_path = os.path.join(os.path.dirname(__file__), "queries/sigma_converted")

for alert in alerts:
    # Her alert için ilgili SPL dosyasını oku
    spl_path = os.path.join(base_path, alert["file"])
    with open(spl_path, "r") as f:
        search = f.read().strip()

    data = {
        "name": alert["name"],
        "search": search,
        "cron_schedule": alert["cron"],
        "is_scheduled": "1",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        
        "disabled": "0",
        "dispatch.earliest_time": "-5m",
        "dispatch.latest_time": "now",
    }

    resp = requests.post(
        f"{SPLUNK_URL}/servicesNS/splunk/search/saved/searches",
        auth=AUTH,
        data=data,
        verify=False
    )

    
    if resp.status_code in (200, 201):
        print(f"[+] Olusturuldu: {alert['name']}")
    elif resp.status_code == 409:
        # Alert zaten var, sil ve yeniden oluştur
        del_resp = requests.delete(
            f"{SPLUNK_URL}/servicesNS/splunk/search/saved/searches/{requests.utils.quote(alert['name'])}",
            auth=AUTH,
            verify=False
        )
        if del_resp.status_code == 200:
            # Yeniden oluştur
            resp2 = requests.post(
                f"{SPLUNK_URL}/servicesNS/splunk/search/saved/searches",
                auth=AUTH,
                data=data,
                verify=False
            )
            if resp2.status_code in (200, 201):
                print(f"[~] Guncellendi: {alert['name']}")
            else:
                print(f"[!] Yeniden olusturma hatasi ({resp2.status_code}): {alert['name']} — {resp2.text[:100]}")
        else:
            print(f"[!] Silme hatasi ({del_resp.status_code}): {alert['name']}")
    else:
        print(f"[!] Hata ({resp.status_code}): {alert['name']} — {resp.text[:100]}")
