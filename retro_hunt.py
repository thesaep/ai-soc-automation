#!/usr/bin/env python3
"""Faz 9 — IOC Retro-Hunt.

Bir IOC'yi (ip/hash/domain) Splunk'ta GECMISE DONUK arar: "bu gosterge daha once
hangi host'ta, ne zaman gorundu?" Bugunku tehdit dunku loglarda gizli olabilir.

Ham Splunk verisini tarar (incidents.json'i degil) — cunku retro-hunt'in isi tam
da detection'in KACIRDIGI yerde IOC var mi bakmaktir. Aktif + arsivlenmis
buckets otomatik kapsanir (Splunk index seviyesinde).
"""
import datetime as dt
from splunk_connector import connect_splunk

try:
    import splunklib.results as results
except ImportError:
    results = None

# IOC tipine gore hangi Splunk alanlarinda aranacak.
# Deger birden fazla alanda gecebilir; hepsini OR ile tarar.
_IOC_FIELDS = {
    "ip": ["SourceIp", "DestinationIp", "Source_Network_Address", "IpAddress", "src_ip", "dest_ip"],
    "hash": ["Hashes", "SHA256", "MD5", "SHA1", "IMPHASH"],
    "domain": ["QueryName", "DestinationHostname", "query", "url_domain"],
}


def _build_spl(ioc_type: str, value: str, earliest: str) -> str:
    """IOC tipine gore alan-hedefli SPL kurar.

    'search index=main (SourceIp="x" OR DestinationIp="x" ...) | ...'
    Alan-hedefli arama, ciplak 'search x'ten hem hizli hem dogru: deger yanlis
    bir alanda gecerse (orn. bir IP'nin bir hash icinde substring olmasi) yakalanmaz.
    """
    fields = _IOC_FIELDS.get(ioc_type, [])
    if not fields:
        raise ValueError(f"bilinmeyen ioc_type: {ioc_type}")
    # hash ve domain buyuk/kucuk harf duyarsiz eslesme icin TERM/alt yaklasim
    clauses = " OR ".join(f'{f}="{value}"' for f in fields)
    return (
        f'search index=main earliest={earliest} ({clauses}) '
        f'| eval _ioc="{value}" '
        f'| stats count as hits min(_time) as first_seen max(_time) as last_seen '
        f'  values(sourcetype) as sourcetypes by host '
        f'| sort -hits'
    )


def retro_hunt(ioc_type: str, value: str, earliest: str = "-90d", service=None) -> dict:
    """Tek IOC icin retro-hunt. Host bazinda ozet dondurur."""
    if service is None:
        service = connect_splunk()
    if service is None:
        return {"ioc_type": ioc_type, "value": value, "error": "splunk baglantisi yok", "matches": []}

    spl = _build_spl(ioc_type, value, earliest)
    job = service.jobs.oneshot(spl, output_mode="json", count=0)

    matches = []
    for r in results.JSONResultsReader(job):
        if isinstance(r, dict) and r.get("host"):
            st = r.get("sourcetypes", [])
            matches.append({
                "host": r["host"],
                "hits": int(r.get("hits", 0)),
                "first_seen": _fmt(r.get("first_seen")),
                "last_seen": _fmt(r.get("last_seen")),
                "sourcetypes": st if isinstance(st, list) else [st],
            })
    return {
        "ioc_type": ioc_type,
        "value": value,
        "window": earliest,
        "host_count": len(matches),
        "total_hits": sum(m["hits"] for m in matches),
        "matches": matches,
    }


def _fmt(epoch) -> str:
    """Splunk epoch -> okunur UTC zaman."""
    try:
        return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return "-"


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="IOC Retro-Hunt")
    ap.add_argument("--ip")
    ap.add_argument("--hash")
    ap.add_argument("--domain")
    # NOT: tire ile baslayan degerler (-90d) argparse tarafindan flag sanilir.
    # '=' kullanimi (--earliest=-90d) veya bu tip icin ozel parse gerekir.
    ap.add_argument("--earliest", default="-90d",
                    help="arama penceresi, orn: --earliest=-30d (tire icin = kullan)")
    a = ap.parse_args()

    pairs = [("ip", a.ip), ("hash", a.hash), ("domain", a.domain)]
    targets = [(t, v) for t, v in pairs if v]
    if not targets:
        ap.error("en az bir IOC ver: --ip / --hash / --domain")

    svc = connect_splunk()
    for ioc_type, value in targets:
        res = retro_hunt(ioc_type, value, a.earliest, service=svc)
        print(f"\n{'='*60}")
        print(f"  RETRO-HUNT: {ioc_type.upper()} = {value}  (window {res['window']})")
        print(f"{'='*60}")
        if res.get("error"):
            print(f"  [-] {res['error']}"); continue
        if not res["matches"]:
            print(f"  [+] Temiz: {res['window']} penceresinde hic gorulmedi")
            continue
        print(f"  [!] {res['host_count']} host, toplam {res['total_hits']} olay:")
        for m in res["matches"]:
            print(f"    {m['host']:20s} | {m['hits']:4d} hit | {m['first_seen']} -> {m['last_seen']}")
            print(f"    {'':20s} | kaynak: {', '.join(m['sourcetypes'])}")
