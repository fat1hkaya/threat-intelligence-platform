"""Log'dan geriye dönük av (retro-hunt): ayıklama Python'da (services/hunt.py), eşleme T-SQL'de (sp_RetroHunt)."""
import json
from collections import Counter

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from ..db import Db, get_db
from ..security import current_user
from ..services.hunt import extract

router = APIRouter(prefix="/api/hunt", tags=["hunt"], dependencies=[Depends(current_user)])

MAX_BYTES = 5 * 1024 * 1024


@router.post("")
async def run_hunt(text: str = Form(""), location: str = Form(..., max_length=100), record: bool = Form(False),
                   file: UploadFile | None = File(None), user: dict = Depends(current_user), db: Db = Depends(get_db)):
    """Log metni veya dosyasındaki IOC'leri veritabanıyla eşleştirir. record=true: eşleşmeler görülme (Sighting) olur."""
    if record and user["Role"] not in ("analyst", "admin"):
        raise HTTPException(403, "Eşleşmeleri görülme olarak kaydetmek için analist yetkisi gerekir.")
    file_name = None
    if file is not None and file.filename:
        raw = await file.read()
        if len(raw) > MAX_BYTES:
            raise HTTPException(400, "Log dosyası 5 MB sınırını aşıyor.")
        text, file_name = raw.decode("utf-8", errors="replace"), file.filename[:200]
    if not text.strip():
        raise HTTPException(400, "Log metni yapıştırın veya bir log dosyası seçin.")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise HTTPException(400, "Log metni 5 MB sınırını aşıyor.")

    ex = extract(text)
    candidates = ex.as_json()
    matches, summary = (db.query_sets(
        "EXEC dbo.sp_RetroHunt @Json = ?, @Location = ?, @Lines = ?, @FileName = ?, @Record = ?, @UserID = ?;",
        (json.dumps(candidates, ensure_ascii=False), location.strip(), ex.lines, file_name, int(record), user["UserID"])) + [[], [{}]])[:2]
    by_type = Counter(c["type"] for c in candidates)
    return {"summary": summary[0] if summary else {}, "matches": matches, "candidatesByType": dict(by_type),
            "truncated": ex.truncated}


@router.get("")
def hunt_history(db: Db = Depends(get_db)):
    return db.query(
        """
        SELECT TOP (30) h.HuntID, h.StartedAt, h.Location, h.FileName, h.LinesScanned, h.Candidates, h.Matches, h.Recorded,
               u.FullName AS StartedBy
        FROM dbo.HuntRun AS h LEFT JOIN dbo.AppUser AS u ON u.UserID = h.StartedBy
        ORDER BY h.HuntID DESC;
        """)


@router.get("/sample")
def sample_log(db: Db = Depends(get_db)):
    """Ekranı denemek için ÖRNEK log satırları: veritabanındaki gerçek IOC'lerden birkaçı rastgele log satırlarına
    gömülür. Bu satırlar gerçek bir ağ trafiği değildir; arayüz bu örnekle 'görülme olarak kaydet'i kapatır."""
    rows = db.query(
        """
        SELECT TOP (6) v.Value, v.TypeCode FROM dbo.vw_Indicator AS v
        WHERE v.Status = 'active' AND v.TypeCode IN ('ipv4', 'domain', 'url', 'sha256')
          AND EXISTS (SELECT 1 FROM dbo.vw_IndicatorAttribution AS a WHERE a.IndicatorID = v.IndicatorID AND a.ActorID IS NOT NULL)
        ORDER BY NEWID();
        """)
    out, n = [], 0
    templates = {
        "ipv4": "2026-11-15T09:{m:02d}:12 fw01 ALLOW TCP 10.10.4.{h}:5{h}21 -> {v}:443 bytes=18234",
        "domain": "2026-11-15T09:{m:02d}:40 dns01 query A cdn.{v} from 10.10.4.{h}",
        "url": "2026-11-15T09:{m:02d}:05 proxy01 GET {v} 200 \"Mozilla/5.0\" user=ws-0{h}",
        "sha256": "2026-11-15T09:{m:02d}:58 edr01 file_written C:\\Users\\Public\\upd.exe sha256={v}",
    }
    for r in rows:
        n += 1
        out.append(f"2026-11-15T09:{n * 7:02d}:00 proxy01 GET https://www.microsoft.com/ 200 user=ws-0{n}")
        out.append(templates[r["TypeCode"]].format(m=n * 7 + 3, h=10 + n, v=r["Value"]))
    return {"text": "\n".join(out) + "\n", "note": "ÖRNEK log: gerçek IOC'ler rastgele log satırlarına gömüldü; görülme olarak kaydedilmemeli."}


@router.get("/{hunt_id}")
def hunt_detail(hunt_id: int, db: Db = Depends(get_db)):
    matches, summary = (db.query_sets("EXEC dbo.sp_HuntResult @HuntID = ?;", (hunt_id,)) + [[], []])[:2]
    if not summary:
        raise HTTPException(404, "Av bulunamadı.")
    return {"summary": summary[0], "matches": matches}
