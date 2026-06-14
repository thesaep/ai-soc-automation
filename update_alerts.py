import requests
import urllib3
import os
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings()

SPLUNK_URL = os.getenv("SPLUNK_URL", "https://localhost:8089")
AUTH = (os.getenv("SPLUNK_USERNAME"), os.getenv("SPLUNK_PASSWORD"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 6=fatal(critical), 5=severe(high), 4=error(medium), 3=warn(low)
alerts = [
    {
        "name": "MITRE T1070 - Event Log Cleared",
        "severity": "6",
        "description": "MITRE T1070.001 - Defense Evasion: Adversary clears Windows Security event log to remove evidence of intrusion.",
        "expires": "24h"
    },
    {
        "name": "MITRE T1069 - LDAP Recon",
        "severity": "4",
        "description": "MITRE T1069 - Discovery: Adversary enumerates domain groups and permissions via LDAP queries.",
        "expires": "24h"
    },
    {
        "name": "MITRE T1082 - Network Recon",
        "severity": "4",
        "description": "MITRE T1082 - Discovery: Adversary performs network reconnaissance to identify targets.",
        "expires": "24h"
    },
    {
        "name": "MITRE T1059 - Obfuscation via MSHTA",
        "severity": "5",
        "description": "MITRE T1059 - Execution: Adversary uses mshta.exe (detected via OriginalFileName=MSHTA.EXE) to execute obfuscated VBScript/JavaScript payloads. Rename-resistant detection.",
        "expires": "24h",
        "spl_file": "queries/sigma_converted/execution/T1059_obfuscation_mshta.spl"
    },
    {
        "name": "MITRE T1059 - Obfuscation via Rundll32",
        "severity": "5",
        "description": "MITRE T1059 - Execution: Adversary uses rundll32.exe (detected via OriginalFileName=RUNDLL32.EXE) to execute obfuscated JavaScript/shellcode payloads. Rename-resistant detection.",
        "expires": "24h",
        "spl_file": "queries/sigma_converted/execution/T1059_obfuscation_rundll32.spl"
    },
    {
        "name": "MITRE T1059 - Obfuscation via Stdin",
        "severity": "5",
        "description": "MITRE T1059 - Execution: Adversary uses stdin-based obfuscation to execute malicious commands.",
        "expires": "24h"
    },
    {
        "name": "MITRE T1078 - External RDP Login",
        "severity": "5",
        "description": "MITRE T1078 - Initial Access: Successful RDP login from external IP address detected.",
        "expires": "24h"
    },
    {
        "name": "MITRE T1078 - External SMB Login",
        "severity": "5",
        "description": "MITRE T1078 - Initial Access: Successful SMB login from external IP address detected.",
        "expires": "24h"
    },
    {
        "name": "MITRE T1078 - Suspicious Failed Logon Reasons",
        "severity": "4",
        "description": "MITRE T1078 - Initial Access: Failed logon attempts with suspicious status/substatus codes.",
        "expires": "24h"
    },
    {
        "name": "MITRE T1078 - Suspicious Failed Logon Source",
        "severity": "4",
        "description": "MITRE T1078 - Initial Access: Failed logon attempts from suspicious external source IPs.",
        "expires": "24h"
    },
    {
        "name": "MITRE T1053 - Suspicious Scheduled Task",
        "severity": "5",
        "description": "MITRE T1053.005 - Persistence: Suspicious scheduled task created in unusual directory.",
        "expires": "24h"
    },
]

labels = {"6": "CRITICAL", "5": "HIGH", "4": "MEDIUM", "3": "LOW"}

for alert in alerts:
    # SPL dosyası tanımlıysa oku, yoksa None
    spl_content = None
    if "spl_file" in alert:
        spl_path = os.path.join(BASE_DIR, alert["spl_file"])
        try:
            with open(spl_path, "r") as f:
                spl_content = f.read().strip()
        except FileNotFoundError:
            print(f"[!] SPL dosyası bulunamadı: {spl_path}")
            continue

    data = {
        "alert.severity": alert["severity"],
        "alert.expires": alert["expires"],
        "description": alert["description"],
    }

    # SPL varsa ekle
    if spl_content:
        data["search"] = spl_content

    resp = requests.post(
        f"{SPLUNK_URL}/servicesNS/splunk/search/saved/searches/{requests.utils.quote(alert['name'])}",
        auth=AUTH,
        data=data,
        verify=False
    )

    if resp.status_code == 200:
        spl_tag = " + SPL" if spl_content else ""
        print(f"[+] {labels[alert['severity']]:8} → {alert['name']}{spl_tag}")
    else:
        print(f"[!] Hata ({resp.status_code}): {alert['name']} — {resp.text[:80]}")
