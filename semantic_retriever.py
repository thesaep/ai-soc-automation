"""
L3 Semantic Retrieval — Faz 8
incidents.json'daki vakaları unique desen bazında ChromaDB'ye indeksler + retrieval.
Embedder: ChromaDB default (all-MiniLM-L6-v2, lokal/offline, 384 boyut).
"""
import glob
from incident_logger import strip_anchors
import json
import chromadb

INCIDENTS_PATH = "logs/incidents.json"
ARCHIVE_GLOB   = "logs/archive/incidents_*.json"   # arsivlenmis segmentler   # kaynak vaka logu (hash-chain)
CHROMA_PATH    = "chroma_db"             # ChromaDB kalıcı depo dizini (git-ignored)
COLLECTION     = "soc_cases"             # koleksiyon adı
MIN_AI_LEN     = 40                      # bu uzunluk altı ai_analysis çöp sayılır, indekslenmez


def load_incidents(path=INCIDENTS_PATH):
    """Aktif + arsivlenmis vakalari birlikte dondurur.

    Arsivleme bir DEPOLAMA islemidir, retrieval'a gorunmez olmalidir. Arsiv
    okunmazsa dosya donduren her arsivleme AI'in gecmis vaka hafizasini
    sessizce siler. Anchor kayitlari vaka degildir, elenir.
    """
    records = []
    for ap in sorted(glob.glob(ARCHIVE_GLOB)):
        try:
            with open(ap, encoding="utf-8") as f:
                records.extend(json.load(f))
        except Exception:
            pass
    try:
        with open(path, encoding="utf-8") as f:
            records.extend(json.load(f))
    except FileNotFoundError:
        pass
    return strip_anchors(records)


def _is_english(ai_text):
    """ai_analysis yeni İngilizce prompt formatında mı? (retrieval kalitesi için kritik)"""
    return "SOC ANALYSIS REPORT" in ai_text or "ATTACK OR FALSE" in ai_text


def select_representatives(records):
    """
    Unique (technique_id, user, host) deseni başına TEK temsilci seçer.
    Temsilci = o desende EN UZUN ai_analysis'e sahip kayıt (en zengin AI yorumu).
    1319 ham kayıt → ~26 anlamlı vaka (şişkinlik temizlenir).
    """
    best = {}
    for r in records:
        ai = r.get("ai_analysis", "").strip()     # AI yorumunu al, boşlukları kırp
        if len(ai) < MIN_AI_LEN:                   # çöp/kısa yorumları ele
            continue
        # AUTO-LOG kayıtları gerçek AI analizi İÇERMEZ (jenerik "eşik altı, izlemede"
        # cümlesi) → embedding'i kirletir, retrieval'da değersiz. İndeks dışı bırak.
        if ai.startswith("[L2 AUTO-LOG]") or ai.startswith("[AUTO-LOG]"):
            continue
        m = r.get("mitre", {})
        e = r.get("entity", {})
        key = (m.get("technique_id"), e.get("user"), e.get("host"))  # benzersizlik anahtarı

        if key not in best:
            best[key] = r                       # bu desen ilk kez görülüyor → al
            continue
        # Çakışma: hangi kayıt daha iyi temsilci?
        # Retrieval İngilizce model kullanıyor → İngilizce analiz HER ZAMAN tercih edilir.
        # _is_english: ai_analysis İngilizce SOC raporu mu (yeni prompt formatı)
        cur = best[key].get("ai_analysis", "").strip()
        new_en = _is_english(ai)                # aday İngilizce mi
        cur_en = _is_english(cur)               # mevcut temsilci İngilizce mi
        if new_en and not cur_en:
            best[key] = r                       # aday EN, mevcut TR → değiştir
        elif new_en == cur_en and len(ai) > len(cur):
            best[key] = r                       # aynı dil → daha uzun olanı al
        # (aday TR, mevcut EN ise dokunma — EN korunur)
    return list(best.values())


def build_document(r):
    """Embedding'e gömülecek SEMANTİK metni kurar (vektörleştirilen kısım)."""
    m = r.get("mitre", {})
    parts = [
        m.get("technique_id", ""),                 # ör. T1078
        m.get("technique_name", ""),               # ör. Valid Accounts
        f"tactic: {m.get('tactic', '')}",          # taktik bağlamı
        f"risk: {r.get('risk', '')}",              # severity bağlamı
        r.get("ai_analysis", "").strip(),          # asıl semantik içerik: AI yorumu
    ]
    return " | ".join(p for p in parts if p)       # boş alanları atlayarak birleştir


def build_metadata(r):
    """Filtre/pivot için metadata (gömülmez; ChromaDB None kabul etmez → hepsi str)."""
    m = r.get("mitre", {})
    e = r.get("entity", {})
    return {
        "technique_id": m.get("technique_id", "") or "",
        "tactic":       m.get("tactic", "") or "",
        "risk":         r.get("risk", "") or "",
        "user":         e.get("user", "") or "",
        "host":         e.get("host", "") or "",
        "src_ip":       e.get("src_ip", "") or "",
        "incident_id":  r.get("incident_id", "") or "",
    }


def index_incidents():
    """incidents.json'ı oku → temsilcileri seç → ChromaDB'ye (yeniden) indeksle."""
    records = load_incidents()
    reps = select_representatives(records)

    client = chromadb.PersistentClient(path=CHROMA_PATH)  # diske yazan kalıcı client
    try:
        client.delete_collection(COLLECTION)   # idempotent: varsa sil, temiz kur
    except Exception:
        pass
    col = client.create_collection(COLLECTION)

    docs  = [build_document(r) for r in reps]
    metas = [build_metadata(r) for r in reps]
    ids   = [f"case_{i}" for i in range(len(reps))]   # sıralı id (incident_id duplike olabilir)

    if docs:
        col.add(documents=docs, metadatas=metas, ids=ids)  # embedding burada üretilir

    print(f"raw records        : {len(records)}")
    print(f"indexed cases      : {len(reps)}")
    print(f"collection count   : {col.count()}")
    print("\n--- sample indexed cases ---")
    for m in metas[:3]:
        print(f"  {m['technique_id']:12} | {m['risk']:8} | user={m['user']} host={m['host']}")


def build_query(event):
    """
    Retrieval SORGUSU için kısa metin (indeks dokümanından FARKLI, ai_analysis YOK).
    Analiz öncesi olaylarda ai_analysis henüz yok; build_document ile sorgu yapmak
    (2000+ karakterlik ai_analysis içeren dokümanlarla kıyaslamak) dist'i yapay şişirir.
    Bu fonksiyon sadece teknik/risk/entity ile kısa, dengeli bir sorgu kurar.
    """
    m = event.get("mitre", {}) or {}
    e = event.get("entity", {}) or {}
    parts = [
        m.get("technique_id") or event.get("detection_type", ""),
        m.get("technique_name", ""),
        f"tactic: {m.get('tactic', '')}" if m.get("tactic") else "",
        f"risk: {event.get('risk', '')}" if event.get("risk") else "",
    ]
    return " | ".join(p for p in parts if p)


def retrieve_similar(query_event, n_results=3, where=None):
    """
    Yeni bir olaya semantik olarak en benzer geçmiş vakaları döndürür (L3 retrieval).
    query_event: dict (canlı olay) VEYA hazır sorgu metni (str).
    where: opsiyonel metadata filtresi, ör. {"risk": "CRITICAL"}.
    """
    # 1) Sorgu metnini kur: dict ise build_document ile (indekslemeyle simetri), str ise olduğu gibi
    qtext = build_query(query_event) if isinstance(query_event, dict) else str(query_event)

    # 2) Kalıcı koleksiyonu aç (indeks önceden kurulmuş olmalı)
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    col = client.get_collection(COLLECTION)

    # 3) Semantik arama: qtext embedding'i ile en yakın n_results vakayı çek
    kwargs = {"query_texts": [qtext], "n_results": n_results}
    if where:                                  # metadata filtresi verildiyse uygula
        kwargs["where"] = where
    res = col.query(**kwargs)

    # 4) Sonuçları düz listeye çevir: metadata + benzerlik mesafesi
    hits = []
    docs  = res.get("documents", [[]])[0]      # eşleşen doküman metinleri
    metas = res.get("metadatas", [[]])[0]      # metadata'lar
    dists = res.get("distances", [[]])[0]      # mesafe (küçük = daha benzer)
    for doc, meta, dist in zip(docs, metas, dists):
        hits.append({
            "technique_id": meta.get("technique_id"),
            "risk":         meta.get("risk"),
            "user":         meta.get("user"),
            "host":         meta.get("host"),
            "incident_id":  meta.get("incident_id"),
            "distance":     round(dist, 4),    # 0'a yakın = çok benzer
            "summary":      doc[:160],
        })
    return hits


if __name__ == "__main__":
    index_incidents()

    # --- retrieval smoke test ---
    print("\n--- RETRIEVAL TEST: 'credential dumping lsass T1003' ---")
    for h in retrieve_similar("credential dumping lsass memory T1003", n_results=3):
        print(f"  dist={h['distance']:.3f} | {h['technique_id']:12} | {h['risk']:8} | {h['summary'][:70]}")
