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


class _C:
    """Terminal renkleri (ai_analyzer/soar_playbook ile ayni ANSI seti)."""
    RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"
    CYA = "\033[96m"; BOLD = "\033[1m"; RST = "\033[0m"


def _mitre_context(ioc_type: str, value: str) -> dict:
    """IOC'nin gecmiste hangi MITRE teknikleriyle iliskili oldugunu bulur.

    Retro-hunt ham Splunk verisini tarar (teknik bilgisi yok); teknik eslesmesi
    incidents.json'da. IP entity.src_ip'de, hash/domain _enrichment veya
    triggered_fields'te aranir. Arsiv+aktif birlikte okunur.
    """
    try:
        from semantic_retriever import load_incidents
        recs = load_incidents()
    except Exception:
        return {"techniques": [], "incident_count": 0}
    techs = {}
    for r in recs:
        hit = False
        if ioc_type == "ip" and r.get("entity", {}).get("src_ip") == value:
            hit = True
        elif value in str(r.get("_enrichment", {})):
            hit = True
        elif value in str(r.get("pipeline_trace", {}).get("triggered_fields", {})):
            hit = True
        if hit:
            m = r.get("mitre", {})
            tid = m.get("technique_id", "?")
            techs.setdefault(tid, {"name": m.get("technique_name", tid), "count": 0})
            techs[tid]["count"] += 1
    ordered = sorted(techs.items(), key=lambda kv: -kv[1]["count"])
    return {
        "techniques": [{"id": t, "name": d["name"], "count": d["count"]} for t, d in ordered],
        "incident_count": sum(d["count"] for _, d in ordered),
    }


def _duration(first: str, last: str) -> str:
    """Iki UTC zaman string'i arasindaki sureyi okunur formatta dondurur."""
    try:
        f = dt.datetime.strptime(first, "%Y-%m-%d %H:%M:%S")
        l = dt.datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
        secs = (l - f).total_seconds()
        if secs < 60:   return f"{int(secs)}sn"
        if secs < 3600: return f"{int(secs//60)}dk"
        if secs < 86400: return f"{secs/3600:.1f}sa"
        return f"{secs/86400:.1f} gun"
    except (ValueError, TypeError):
        return "-"



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
    _mitre = _mitre_context(ioc_type, value)
    return {
        "ioc_type": ioc_type,
        "value": value,
        "window": earliest,
        "host_count": len(matches),
        "total_hits": sum(m["hits"] for m in matches),
        "matches": matches,
        "mitre": _mitre,
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
        # Yayilim siddeti gostergesi
        hc = res["host_count"]
        if hc > 2:
            sev = f"{_C.RED}{_C.BOLD}[SPREAD]{_C.RST} {_C.RED}{hc} host'a yayilmis{_C.RST}"
        elif hc == 2:
            sev = f"{_C.YEL}[SPREAD]{_C.RST} {_C.YEL}2 host{_C.RST}"
        else:
            sev = f"{_C.GRN}[SINGLE]{_C.RST} tek host"
        print(f"  {sev}  |  toplam {_C.BOLD}{res['total_hits']}{_C.RST} olay")
        print(f"  {'-'*56}")
        for m in res["matches"]:
            dur = _duration(m["first_seen"], m["last_seen"])
            # hit yogunlugu: gun basina ortalama
            try:
                days = max((dt.datetime.strptime(m["last_seen"], "%Y-%m-%d %H:%M:%S")
                            - dt.datetime.strptime(m["first_seen"], "%Y-%m-%d %H:%M:%S")).total_seconds()/86400, 1)
                rate = f"~{m['hits']/days:.0f}/gun"
            except Exception:
                rate = "-"
            print(f"  {_C.CYA}{m['host']:22s}{_C.RST} {m['hits']:>6d} hit  ({rate}, {dur} aktif)")
            print(f"  {'':22s} {m['first_seen']} -> {m['last_seen']}")
            print(f"  {'':22s} kaynak: {', '.join(m['sourcetypes'])}")
        # MITRE teknik baglami
        mitre = res.get("mitre", {})
        if mitre.get("techniques"):
            print(f"  {'-'*56}")
            print(f"  {_C.BOLD}MITRE baglami{_C.RST} ({mitre['incident_count']} incident'ta gorulmus):")
            for t in mitre["techniques"][:6]:
                print(f"    {_C.YEL}{t['id']:12s}{_C.RST} {t['name'][:36]:36s} x{t['count']}")
        else:
            print(f"  {'-'*56}")
            print(f"  MITRE baglami: bu IOC hic incident'a bagli degil (sadece ham veride)")
