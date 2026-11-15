"""Malpedia (Fraunhofer FKIE) aile listesi: diğer adlar ve aile -> aktör atıfları.

Kullanım:  python -m importers malpedia
- Anahtarsız uç nokta: https://malpedia.caad.fkie.fraunhofer.de/api/get/families (yaklaşık 4 MB, tek istek)
- Veri lisansı: CC BY-SA 4.0. Her ilişkinin kanıtı Malpedia aile sayfasına bağlantı verir.
- İşlem veritabanında dbo.sp_ImportMalpedia ile yapılır: takma ad ekleme, aynı aileye düşen besleme
  kayıtlarını birleştirme (sp_MergeMalware), aktör atıflarını kanıtlı ilişki olarak yazma.
"""
import json
import time
import urllib.request

from ._db import source_id

URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/families"
UA = "ThreatLens/1.0 (universite VTYS projesi)"


class MalpediaError(RuntimeError):
    pass


def fetch() -> list[dict]:
    try:
        with urllib.request.urlopen(urllib.request.Request(URL, headers={"User-Agent": UA}), timeout=120) as r:
            data = json.loads(r.read())
    except Exception as exc:  # ağ, zaman aşımı, bozuk yanıt
        raise MalpediaError(f"Malpedia alınamadı: {exc}") from exc
    return [{"id": fid, "name": (f.get("common_name") or fid)[:150],
             "alt": [a for a in (f.get("alt_names") or []) if a][:40],
             "actors": [a for a in (f.get("attribution") or []) if a][:60]}
            for fid, f in data.items()]


def run(conn) -> dict:
    cur = conn.cursor()
    src = source_id(conn, "Malpedia")
    job = cur.execute("EXEC dbo.sp_StartImportJob @SourceID = ?, @JobType = 'feed', @FileName = ?;", src, "api/get/families").fetchone()[0]
    started = time.perf_counter()
    try:
        families = fetch()
        row = cur.execute("EXEC dbo.sp_ImportMalpedia @Json = ?, @JobID = ?;", json.dumps(families, ensure_ascii=False), job).fetchone()
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?;", job).fetchone()
        return {"job_id": job, "status": "success", "families": row.Families, "merged": row.Merged, "aliases": row.AliasesAdded,
                "actor_links": row.ActorLinksAdded, "seconds": round(time.perf_counter() - started, 1)}
    except Exception as exc:
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?, @Status = 'failed', @ErrorMessage = ?;", job, str(exc)[:1000]).fetchone()
        return {"job_id": job, "status": "failed", "message": str(exc)}
