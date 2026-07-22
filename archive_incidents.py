#!/usr/bin/env python3
"""Hash-chain guvenli segment arsivleme (logs/incidents.json).

Kayit SILMEZ: eski segmenti logs/archive/ altina tasir, aktif dosyanin basina
zincir baglantisini tasiyan bir ANCHOR kaydi koyar. Kesim noktasi korelasyon
penceresinden (240dk) buyuk bir zaman bosluguna denk gelmek ZORUNDA - aksi
halde bir kill-chain zinciri ortadan bolunur.
"""
import json, os, shutil, argparse, datetime as dt
from incident_logger import (_compute_hash, _is_anchor, ANCHOR_TYPE,
                             LOG_FILE, verify_chain)

ARCHIVE_DIR = "logs/archive"
WINDOW_MIN  = 240

def _ts(r): return dt.datetime.fromisoformat(r.get("timestamp","").replace("Z","+00:00"))

def _safe_cuts(body):
    out = []
    for i in range(1, len(body)):
        try:
            if (_ts(body[i]) - _ts(body[i-1])).total_seconds() > WINDOW_MIN*60:
                out.append(i)
        except Exception:
            pass
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", type=int, default=200, help="aktif dosyada kalacak asgari kayit")
    ap.add_argument("--apply", action="store_true", help="yaz (varsayilan: dry-run)")
    a = ap.parse_args()

    with open(LOG_FILE, encoding="utf-8") as f:
        recs = json.load(f)
    prev_anchor = recs[0] if recs and _is_anchor(recs[0]) else None
    body = recs[1:] if prev_anchor else recs

    cuts = _safe_cuts(body)
    cand = [c for c in cuts if len(body) - c >= a.keep]
    if not cand:
        print(f"[-] Guvenli kesim yok (kayit={len(body)}, keep={a.keep}, aday={len(cuts)})")
        return
    cut = max(cand)
    seg, rest = body[:cut], body[cut:]
    gap = (_ts(rest[0]) - _ts(seg[-1])).total_seconds()/3600

    print(f"    arsivlenecek : {len(seg)} kayit  ({seg[0]['timestamp'][:10]} -> {seg[-1]['timestamp'][:10]})")
    print(f"    aktif kalacak: {len(rest)} kayit")
    print(f"    kesim boslugu: {gap:.1f}h  (esik {WINDOW_MIN/60:.0f}h)")
    if not a.apply:
        print("[*] DRY-RUN - yazmak icin --apply")
        return

    if not verify_chain():
        print("[-] Zincir dogrulanamadi - arsivleme IPTAL"); return

    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    name = f"incidents_{seg[0]['timestamp'][:10]}_{seg[-1]['timestamp'][:10]}.json"
    path = os.path.join(ARCHIVE_DIR, name)
    if os.path.exists(path):
        print(f"[-] {path} zaten var - IPTAL"); return
    shutil.copy2(LOG_FILE, LOG_FILE + ".pre-archive.bak")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(seg, f, ensure_ascii=False, indent=2)

    anchor = {
        "record_type":      ANCHOR_TYPE,
        "schema_version":   "2.1",
        "created_at":       dt.datetime.now(dt.timezone.utc).isoformat(),
        "archived_file":    name,
        "archived_count":   len(seg) + (prev_anchor.get("archived_count",0) if prev_anchor else 0),
        "archived_range":   [seg[0]["timestamp"], seg[-1]["timestamp"]],
        "prev_anchor_hash": prev_anchor.get("hash") if prev_anchor else None,
        "archived_last_hash": seg[-1].get("hash",""),
        "hash": "",
    }
    anchor["hash"] = _compute_hash({k:v for k,v in anchor.items() if k!="hash"},
                                   anchor["archived_last_hash"])
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump([anchor] + rest, f, ensure_ascii=False, indent=2)

    print(f"[+] Arsiv: {path} ({len(seg)} kayit)")
    print(f"[+] Aktif: {LOG_FILE} (anchor + {len(rest)} kayit)")
    verify_chain()

if __name__ == "__main__":
    main()
