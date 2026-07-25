#!/usr/bin/env python3
"""Faz 9 — SOC Izleme Dashboard'u (salt-okunur).

Veri kaynagi: incidents.json + arsiv + KB (DOSYA-TABANLI, Splunk'a bagimsiz).
Pipeline'in URETTIGI sonucu gorsellestirir; ham Splunk'i tekrar sorgulamaz.
Etkilesimli hunt/retro-hunt tetikleme Faz 11'e birakildi (bu salt-okunur).

Calistirma:  streamlit run dashboard.py
"""
import json
import collections
import datetime as dt
import streamlit as st
import pandas as pd
import plotly.express as px

# ── Veri katmani (sema-toleransli okuyucular) ──────────────────────────────

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLOR = {"CRITICAL": "#d32f2f", "HIGH": "#f57c00", "MEDIUM": "#fbc02d", "LOW": "#388e3c"}

# Maskeleme: SS/paylasim icin gercek host adlarini anonimlestir.
MASK_MAP = {"DESKTOP-1BT9MN3": "WORKSTATION-01", "DESKTOP-VNEKQ7O": "LAB-TARGET-01"}


@st.cache_data(ttl=30)
def load_data():
    """incidents.json + arsiv + KB oku. Anchor kayitlarini eler."""
    from semantic_retriever import load_incidents
    recs = [r for r in load_incidents() if not r.get("record_type")]
    try:
        kb = json.load(open("logs/knowledge_base.json", encoding="utf-8"))
    except Exception:
        kb = []
    return recs, kb


def _sev(r) -> str:
    """severity guvenli cikar: risk string olabilir de dict de (sema toleransi)."""
    rk = r.get("risk")
    if isinstance(rk, dict):
        return rk.get("severity", "-")
    if isinstance(rk, str):
        return rk
    return "-"


def _tech(r) -> tuple:
    m = r.get("mitre", {})
    return m.get("technique_id", "?"), m.get("technique_name", "?")


def _host(r, mask: bool) -> str:
    h = r.get("entity", {}).get("host", "-")
    return MASK_MAP.get(h, h) if mask else h


def _mask_entity(user: str, host: str, mask: bool) -> str:
    """user@host string'i maskele. user icindeki host adini da (DOMAIN\\user) temizle."""
    h = MASK_MAP.get(host, host) if mask else host
    u = user
    if mask:
        for real, fake in MASK_MAP.items():
            u = u.replace(real, fake)
    return f"{u}@{h}"


def _ts(r) -> str:
    return r.get("timestamp", "")


def _verdict(r) -> str:
    return r.get("pipeline_trace", {}).get("triage_verdict", "-")


# ── Ana sayfa iskeleti (paneller sonra eklenecek) ──────────────────────────


def _verify_active():
    """verify_chain'i cagirip stdout yerine ozet dondur."""
    import io, contextlib, incident_logger as il
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = il.verify_chain()
    out = buf.getvalue()
    # ozet satiri: 'Chain verified: N/M' veya kirilma
    line = next((l for l in out.splitlines() if "verified" in l or "broken" in l or "unverifiable" in l), "-")
    return ok, line.strip().lstrip("[+!-] ")


def _verify_archive():
    import io, contextlib, incident_logger as il
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = il.verify_archive()
    out = buf.getvalue()
    line = next((l for l in out.splitlines() if "Archive verified" in l or "No archive" in l or "broken" in l), "-")
    return ok, line.strip().lstrip("[+!-] ")


def main():
    st.set_page_config(page_title="SOC Dashboard", layout="wide", page_icon="🛡️")
    recs, kb = load_data()

    # Sidebar: maskeleme + kaynak bilgisi
    st.sidebar.title("🛡️ SOC Monitor")
    mask = st.sidebar.toggle("Host maskeleme (SS icin)", value=True,
                             help="Gercek host adlarini paylasim icin anonimlestirir")
    st.sidebar.caption(f"Kaynak: {len(recs)} incident + {len(kb)} KB kaydi")
    st.sidebar.caption("Salt-okunur · dosya-tabanli")

    st.title("SOC Automation — Izleme Paneli")
    st.caption(f"Son guncelleme: {dt.datetime.now().strftime('%Y-%m-%d %H:%M')} · "
               f"{len(recs)} toplam incident (aktif + arsiv)")

    # PANEL 1 test: ozet kartlari
    sev_counts = collections.Counter(_sev(r) for r in recs)
    verdict_counts = collections.Counter(_verdict(r) for r in recs)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Toplam Incident", len(recs))
    c2.metric("CRITICAL", sev_counts.get("CRITICAL", 0))
    c3.metric("HIGH", sev_counts.get("HIGH", 0))
    c4.metric("ESCALATE", verdict_counts.get("ESCALATE", 0))

    st.divider()

    # ── PANEL: Hash-Chain Butunluk ──────────────────────────────────
    st.subheader("🔗 Hash-Chain Butunlugu")
    hc1, hc2 = st.columns(2)
    active_ok, active_msg = _verify_active()
    arch_ok, arch_msg = _verify_archive()
    with hc1:
        if active_ok:
            st.success(f"✅ Aktif zincir dogrulandi\n\n{active_msg}")
        else:
            st.error(f"❌ Aktif zincir SORUNLU\n\n{active_msg}")
    with hc2:
        if arch_ok:
            st.success(f"✅ Arsiv muhurlu\n\n{arch_msg}")
        else:
            st.error(f"❌ Arsiv SORUNLU\n\n{arch_msg}")
    st.caption("Append-only SHA256 zincir · mutable alanlar (count/last_seen) hash disi · "
               "arsiv anchor ile aktif zincire kriptografik bagli")

    st.divider()

    # ── PANEL: MITRE teknik dagilimi + severity ─────────────────────
    # mitre_panel
    mc1, mc2 = st.columns([2, 1])
    with mc1:
        st.subheader("🎯 MITRE ATT&CK — Teknik Dagilimi")
        tech_counts = collections.Counter(_tech(r)[0] for r in recs)
        tech_names = {tid: name for tid, name in (_tech(r) for r in recs)}
        top = tech_counts.most_common(12)
        df_t = pd.DataFrame([
            {"Teknik": f"{tid}", "Ad": tech_names.get(tid, tid)[:30], "Adet": n}
            for tid, n in top
        ])
        fig = px.bar(df_t, x="Adet", y="Teknik", orientation="h",
                     hover_data=["Ad"], text="Adet",
                     color="Adet", color_continuous_scale="Oranges")
        fig.update_layout(height=380, margin=dict(l=0, r=0, t=10, b=0),
                          yaxis={"categoryorder": "total ascending"},
                          coloraxis_showscale=False, paper_bgcolor="rgba(0,0,0,0)",
                          plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    with mc2:
        st.subheader("Severity")
        sev_c = collections.Counter(_sev(r) for r in recs)
        df_s = pd.DataFrame([
            {"Severity": s, "Adet": sev_c.get(s, 0)}
            for s in SEV_ORDER if sev_c.get(s, 0) > 0
        ])
        fig2 = px.pie(df_s, values="Adet", names="Severity", hole=0.5,
                      color="Severity", color_discrete_map=SEV_COLOR)
        fig2.update_layout(height=380, margin=dict(l=0, r=0, t=10, b=0),
                           showlegend=True, paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # ── PANEL: Zaman cizgisi (gun bazinda incident) ─────────────────
    # timeline_panel
    st.subheader("📈 Incident Zaman Cizgisi (gun bazinda)")
    day_counts = collections.Counter()
    for r in recs:
        ts = _ts(r)
        if len(ts) >= 10:
            day_counts[ts[:10]] += 1
    if day_counts:
        df_d = pd.DataFrame(sorted(day_counts.items()), columns=["Gun", "Adet"])
        fig3 = px.area(df_d, x="Gun", y="Adet", markers=True)
        fig3.update_traces(line_color="#f57c00", fillcolor="rgba(245,124,0,0.2)")
        fig3.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0),
                           paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig3, use_container_width=True)

    st.divider()

    # ── PANEL: Son incident'lar (maskeleme uygulanir) ───────────────
    st.subheader("📋 Son Incident'lar")
    recent = sorted([r for r in recs if _ts(r)], key=_ts, reverse=True)[:20]
    rows = []
    for r in recent:
        tid, tname = _tech(r)
        rows.append({
            "Zaman": _ts(r)[:19].replace("T", " "),
            "Host": _host(r, mask),
            "Teknik": tid,
            "Ad": tname[:32],
            "Severity": _sev(r),
            "Verdict": _verdict(r),
        })
    df_r = pd.DataFrame(rows)
    st.dataframe(df_r, use_container_width=True, hide_index=True,
                 column_config={"Severity": st.column_config.TextColumn(width="small")})

    st.divider()

    # ── PANEL: Aktif Case'ler (Faz 9.5) ─────────────────────────────
    # case_panel
    st.subheader("🗂️ Sorusturma Case'leri")
    try:
        from case_manager import list_cases
        cases = list_cases()
    except Exception:
        cases = []
    if not cases:
        st.caption("Henuz Case yok — pipeline kill-chain uretince olusur")
    else:
        oc1, oc2, oc3 = st.columns(3)
        oc1.metric("Toplam Case", len(cases))
        oc2.metric("CRITICAL/HIGH", sum(1 for c in cases if c.get("chain_risk") in ("CRITICAL", "HIGH")))
        oc3.metric("Multi-stage", sum(1 for c in cases if c.get("is_multistage")))
        case_rows = []
        for c in cases[:25]:
            ent = c.get("entity", {})
            case_rows.append({
                "Case UID": c.get("correlation_uid", "-"),
                "Entity": _mask_entity(ent.get("user", "-"), ent.get("host", "-"), mask),
                "Risk": c.get("chain_risk", "-"),
                "Incident": c.get("incident_count", 0),
                "Teknik": ", ".join(c.get("techniques", [])[:4]),
                "Kill-Chain": " -> ".join(c.get("tactics", [])[:4]),
                "Retro": len(c.get("retro_hunts", [])),
                "Status": c.get("status", "-"),
            })
        st.dataframe(pd.DataFrame(case_rows), use_container_width=True, hide_index=True)
        st.caption("Correlation UID deterministik (ayni zincir hep ayni Case) · "
                   "durum degistirme + not ekleme Faz 11'de")

    st.divider()

    # ── PANEL: Knowledge Base ozeti ─────────────────────────────────
    st.subheader("📚 Knowledge Base — Mesru-Arac Istisnalari")
    if kb:
        kb_rows = [{
            "Tip": e.get("kb_type", "-"),
            "Gosterge": e.get("indicator", e.get("pattern", "-"))[:40],
            "Scope": e.get("scope", "-"),
            "Sebep": e.get("reason", e.get("resolution", "-"))[:50],
        } for e in kb]
        st.dataframe(pd.DataFrame(kb_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("KB bos")


if __name__ == "__main__":
    main()
