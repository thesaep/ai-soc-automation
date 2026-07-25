#!/usr/bin/env python3
"""Faz 9 — Statik Hunt Kutuphanesi calistirici (hipotez-bazli hunting).

Retro-hunt REAKTIF'tir (IOC gelince tetiklenir). Bu hunt'lar PROAKTIF'tir:
analist bir hipotezle calistirir ("bir saldirgan buradaysa sunu yapiyor olurdu").
Detection DEGIL — otomatik alert uretmez, incident'a yazmaz, Claude'a gitmez.
Sonuc analist yorumuna birakilir; deger insan degerlendirmesindedir.
"""
import os
import glob
import datetime as dt
from splunk_connector import connect_splunk, _mv_last

try:
    import splunklib.results as results
except ImportError:
    results = None

HUNT_DIR = "queries/hunting"

# Her hunt icin analist-okunur hipotez. Dosya adi -> aciklama.
HYPOTHESES = {
    "H001_lolbin_download": "certutil/bitsadmin bir indirme araci olarak kullaniliyor olabilir (LOLBin abuse)",
    "H002_encoded_powershell": "Gizlenmis/encoded PowerShell komutu calistiriliyor olabilir (defense evasion)",
    "H003_office_spawns_shell": "Bir Office uygulamasi shell doguruyor olabilir (makro tabanli initial access)",
}


class _C:
    RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"
    CYA = "\033[96m"; BOLD = "\033[1m"; RST = "\033[0m"


def run_hunt(spl_file: str, earliest: str, service) -> dict:
    """Tek hunt SPL'ini calistirir, satirlari dondurur."""
    with open(spl_file, encoding="utf-8") as f:
        spl = f.read().strip()
    # SPL 'search' ile baslamiyorsa ekle (dosyalar source=... ile basliyor)
    if not spl.lower().startswith("search"):
        spl = "search " + spl
    spl = f"{spl} | head 50" if "| head" not in spl else spl
    # earliest'i basa enjekte et
    spl = spl.replace("search ", f"search earliest={earliest} ", 1)

    job = service.jobs.oneshot(spl, output_mode="json", count=0)
    rows = [r for r in results.JSONResultsReader(job) if isinstance(r, dict)]
    return {"file": os.path.basename(spl_file), "count": len(rows), "rows": rows}


def _fmt_time(epoch) -> str:
    try:
        return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).strftime("%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(epoch)[:19]


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Statik hunt kutuphanesi calistirici")
    ap.add_argument("--hunt", help="tek hunt kodu (orn: H001). Bos ise HEPSI calisir.")
    ap.add_argument("--earliest", default="-7d", help="arama penceresi, orn: --earliest=-24h")
    ap.add_argument("--host", help="belirli bir host'a filtrele (orn: DESKTOP-VNEKQ7O)")
    a = ap.parse_args()

    files = sorted(glob.glob(f"{HUNT_DIR}/*.spl"))
    if a.hunt:
        files = [f for f in files if os.path.basename(f).startswith(a.hunt)]
        if not files:
            ap.error(f"{a.hunt} ile eslesen hunt yok. Mevcut: {HUNT_DIR}/")

    svc = connect_splunk()
    if svc is None:
        print("[-] Splunk baglantisi yok"); return

    total_hits = 0
    for spl_file in files:
        key = os.path.basename(spl_file).replace(".spl", "")
        hypo = HYPOTHESES.get(key, "-")
        res = run_hunt(spl_file, a.earliest, svc)
        # host filtresi (opsiyonel, sonuc uzerinde)
        if a.host:
            res["rows"] = [r for r in res["rows"] if r.get("ComputerName") == a.host]
            res["count"] = len(res["rows"])
        total_hits += res["count"]

        print(f"\n{'='*64}")
        print(f"  {_C.BOLD}{key}{_C.RST}  (window {a.earliest})")
        print(f"  {_C.CYA}Hipotez:{_C.RST} {hypo}")
        print(f"{'='*64}")
        if res["count"] == 0:
            print(f"  {_C.GRN}[TEMIZ]{_C.RST} eslesme yok")
            continue
        print(f"  {_C.RED}{_C.BOLD}[{res['count']} BULGU]{_C.RST} - analist incelemesi gerekli:")
        for r in res["rows"][:15]:
            t = _fmt_time(_mv_last(r.get("_time", "-")))
            img = str(_mv_last(r.get("Image", "") or r.get("ParentImage", "") or "-")).split("\\")[-1]
            cmd = str(_mv_last(r.get("CommandLine", "-")))[:70]
            host = _mv_last(r.get("ComputerName", "-"))
            user = str(_mv_last(r.get("User", "-"))).split("\\")[-1]
            print(f"    {t} | {_C.CYA}{host:16s}{_C.RST} | {user:10s} | {img}")
            print(f"    {'':17s} {cmd}")
        if res["count"] > 15:
            print(f"    ... +{res['count']-15} daha (SPL'i Splunk'ta calistir)")

    print(f"\n{'='*64}")
    verdict = f"{_C.RED}{total_hits} toplam bulgu{_C.RST}" if total_hits else f"{_C.GRN}tum hunt'lar temiz{_C.RST}"
    print(f"  OZET: {len(files)} hunt calisti | {verdict}")


if __name__ == "__main__":
    main()
