#!/usr/bin/env python3
"""
kb_add.py — Faz 8.6 Knowledge Base hizli istisna girme araci
Yetkili tek komutla mesru-arac istisnasi veya closed-case bilgisi ekler.

Ornekler:
  # IP prefix istisnasi (belirli tekniklere)
  python3 kb_add.py --ip-prefix "100." --reason "Tailscale VPN" --techniques T1078,T1550.002

  # Process istisnasi
  python3 kb_add.py --process "OneDriveSetup.exe" --reason "MS OneDrive update" --techniques T1547.001

  # Tam IP istisnasi (global, teknik filtresi yok)
  python3 kb_add.py --ip "8.8.8.8" --reason "Google DNS"

  # Domain istisnasi
  python3 kb_add.py --domain "update.microsoft.com" --reason "MS Update"

  # Closed-case pattern
  python3 kb_add.py --close-case <incident_id> --pattern "..." --resolution false_positive --techniques T1078

  # Mevcut KB'yi listele
  python3 kb_add.py --list
"""

import argparse
import sys
from knowledge_base import (
    add_legitimate_tool, add_closed_case, get_kb_summary, _load_kb
)


def _parse_techniques(s: str) -> list:
    """virgullu teknik string'ini listeye cevir: 'T1078,T1550.002' -> [...]"""
    if not s:
        return []
    return [t.strip() for t in s.split(",") if t.strip()]


def main():
    p = argparse.ArgumentParser(description="Knowledge Base hizli istisna girme")
    # Mesru-arac tipleri (biri secilir)
    p.add_argument("--ip-prefix", help="IP prefix istisnasi (orn. '100.')")
    p.add_argument("--ip", help="Tam IP istisnasi")
    p.add_argument("--process", help="Process adi istisnasi (orn. 'OneDriveSetup.exe')")
    p.add_argument("--domain", help="Domain istisnasi")
    # Closed-case
    p.add_argument("--close-case", metavar="INCIDENT_ID", help="Kapanmis vaka bilgisi ekle")
    p.add_argument("--pattern", help="Closed-case pattern aciklamasi")
    p.add_argument("--resolution", choices=["false_positive", "true_positive", "benign_expected"],
                   help="Closed-case cozum tipi")
    # Ortak
    p.add_argument("--reason", help="Istisna gerekcesi (insan-okunur)")
    p.add_argument("--techniques", help="Ilgili MITRE teknikleri (virgullu). Bos = global")
    p.add_argument("--added-by", default="analyst", help="Ekleyen (varsayilan: analyst)")
    p.add_argument("--scope", choices=["infrastructure", "detection"], default="detection",
                   help="infrastructure=global (her teknik) | detection=teknik-filtreli (VARSAYILAN, guvenli)")
    # Listeleme
    p.add_argument("--list", action="store_true", help="Mevcut KB kayitlarini listele")

    args = p.parse_args()
    techs = _parse_techniques(args.techniques)

    if args.list:
        entries = _load_kb()
        print(f"\n=== Knowledge Base ({len(entries)} kayit) ===\n")
        for e in entries:
            if e["kb_type"] == "legitimate_tool":
                sc = e.get("scope", "detection")
                t = ("GLOBAL" if sc == "infrastructure"
                     else (",".join(e.get("techniques", [])) or "NO-TECH"))
                print(f"  [LEGIT] {e['indicator_type']:10} {e['indicator']:24} | {sc:14} | {t}")
                print(f"          {e['reason']}")
            else:
                t = ",".join(e.get("techniques", [])) or "-"
                print(f"  [CASE]  {e['resolution']:16} | {t}")
                print(f"          {e['pattern']}")
        print()
        return

    # Mesru-arac ekleme
    tool_map = [
        (args.ip_prefix, "ip_prefix"),
        (args.ip,        "ip"),
        (args.process,   "process"),
        (args.domain,    "domain"),
    ]
    for indicator, itype in tool_map:
        if indicator:
            if not args.reason:
                print("[HATA] --reason zorunlu", file=sys.stderr)
                sys.exit(1)
            e = add_legitimate_tool(indicator, itype, args.reason, techs, args.added_by, args.scope)
            if args.scope == "infrastructure":
                scope_desc = "GLOBAL/infrastructure (tum teknikler)"
            else:
                scope_desc = ("detection: " + (",".join(techs) if techs else "HICBIR TEKNIK - uyari: techniques bos!"))
            print(f"[OK] Mesru-arac eklendi: {itype} '{indicator}' -> {scope_desc}")
            print(f"     Gerekce: {args.reason}")
            return

    # Closed-case ekleme
    if args.close_case:
        if not args.pattern or not args.resolution:
            print("[HATA] --pattern ve --resolution zorunlu", file=sys.stderr)
            sys.exit(1)
        e = add_closed_case(args.close_case, args.pattern, args.resolution, techs, args.added_by)
        print(f"[OK] Closed-case eklendi: {args.resolution} | teknik: {','.join(techs) or '-'}")
        print(f"     Pattern: {args.pattern}")
        return

    p.print_help()


if __name__ == "__main__":
    main()
