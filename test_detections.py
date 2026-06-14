#!/usr/bin/env python3
"""
Tüm MITRE detection'ları çalıştırıp hangisinin kaç event döndürdüğünü raporlar.
Kullanım: python3 test_detections.py [earliest]
Örnek:    python3 test_detections.py -30d
"""
import sys
from splunk_connector import connect_splunk, get_all_mitre_events

earliest = sys.argv[1] if len(sys.argv) > 1 else "-7d"

print(f"\n{'='*60}")
print(f"DETECTION TEST — pencere: {earliest}")
print(f"{'='*60}\n")

service = connect_splunk()
events = get_all_mitre_events(service, earliest=earliest)

# Detection bazında say
from collections import Counter
counts = Counter(e.get('detection_type', 'UNKNOWN') for e in events)

print(f"\n{'='*60}")
print(f"ÖZET — toplam {len(events)} event, {len(counts)} detection tetiklendi")
print(f"{'='*60}")
for det, n in sorted(counts.items(), key=lambda x: -x[1]):
    print(f"  {n:>4}  {det}")

if not counts:
    print("  (hiç event yok — pencereyi genişlet veya test trafiği üret)")
