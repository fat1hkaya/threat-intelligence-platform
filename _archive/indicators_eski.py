import json

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..db import Db, get_db
from ..security import current_user, require_analyst

router = APIRouter(prefix="/api/indicators", tags=["indicators"], dependencies=[Depends(current_user)])

SORTS = {"lastSeen": "v.LastSeen", "risk": "v.RiskScore", "confidence": "v.Confidence",
         "value": "v.Value", "firstSeen": "v.FirstSeen", "sightings": "v.SightingCount"}


@router.get("")
def list_indicators(
    q: str = "", type: str = "", severity: str = "", tlp: str = "", source: int | None = None, tag: str = "",
    active: bool | None = None, sighted: bool | None = None, minRisk: int = Query(0, ge=0, le=100),
    sort: str = "lastSeen", dir: str = "desc", page: int = Query(1, ge=1), size: int = Query(25, ge=5, le=200),
    db: Db = Depends(get_db),
):
    # WHERE koşulları sabit parçalardan kurulur; kullanıcı girdisi yalnızca parametre (?) olarak geçer
    where, params = ["1 = 1"], []
    if q.strip():
        where.append("v.Value LIKE ?")
        params.append(f"%{q.strip()}%")
    if type:
        where.append("v.TypeCode = ?"); params.append(type)
    if severity:
        where.append("v.SeverityCode = ?"); params.append(severity)
    if tlp:
        where.append("v.TLPCode = ?"); params.append(tlp)
    if source:
        where.append("v.SourceID = ?"); params.append(source)
    if active is not None:
        where.append("v.IsActive = ?"); params.append(int(active))
    if sighted:
        where.append("v.SightingCount > 0")
    if minRisk:
        where.append("v.RiskScore >= ?"); params.append(minRisk)
    if tag:
        where.append("""EXISTS (SELECT 1 FROM dbo.IndicatorTag AS it JOIN dbo.Tag AS tg ON tg.TagID = it.TagID
                    WHERE it.IndicatorID = v.IndicatorID AND tg.Name = ?)""")
        params.append(tag)
    clause = "\n          AND ".join(where)
    order = f"{SORTS.get(sort, 'v.LastSeen')} {'ASC' if dir == 'asc' else 'DESC'}, v.IndicatorID DESC"

    total = db.scalar(f"SELECT COUNT(*) AS Total FROM dbo.vw_Indicator AS v\n        WHERE {clause};", tuple(params))
    items = db.query(
        f"""
        SELECT v.IndicatorID, v.Value, v.TypeCode, v.TypeName, v.Confidence, v.SeverityCode, v.SeverityName, v.TLPCode,
               v.SourceName, v.Reliability, v.FirstSeen, v.LastSeen, v.IsActive, v.SightingCount, v.RiskScore,
               (SELECT STRING_AGG(tg.Name, ',') FROM dbo.IndicatorTag AS it
                  JOIN dbo.Tag AS tg ON tg.TagID = it.TagID WHERE it.IndicatorID = v.IndicatorID) AS Tags,
               (SELECT TOP (1) a.ViaName FROM dbo.vw_IndicatorAttribution AS a WHERE a.IndicatorID = v.IndicatorID) AS ViaName
        FROM dbo.vw_Indicator AS v
        WHERE {clause}
        ORDER BY {order}
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;      -- sayfalama
        """, tuple(params) + ((page - 1) * size, size))
    for item in items:
        item["Tags"] = item["Tags"].split(",") if item["Tags"] else []
    return {"items": items, "total": total, "page": page, "size": size}


class BulkCheck(BaseModel):
    values: list[str] = Field(max_length=2000)


@router.post("/lookup")
def bulk_lookup(body: BulkCheck, db: Db = Depends(get_db)):
    """Yapıştırılan IOC listesinden hangileri bizde kayıtlı?"""
    cleaned = sorted({v.strip() for v in body.values if v.strip()})
    if not cleaned:
        return {"asked": 0, "matches": [], "unknown": []}
    matches = db.query(
        """
        -- Liste JSON olarak tek parametrede gelir; OPENJSON ile tabloya açılıp JOIN edilir
        SELECT j.[value] AS Asked, v.IndicatorID, v.Value, v.TypeCode, v.RiskScore, v.SeverityCode, v.IsActive,
               v.LastSeen, v.SourceName,
               (SELECT TOP (1) a.ViaName FROM dbo.vw_IndicatorAttribution AS a WHERE a.IndicatorID = v.IndicatorID) AS ViaName,
               (SELECT TOP (1) a.ActorName FROM dbo.vw_IndicatorAttribution AS a
                 WHERE a.IndicatorID = v.IndicatorID AND a.ActorName IS NOT NULL) AS ActorName
        FROM OPENJSON(?) AS j
        JOIN dbo.vw_Indicator AS v ON v.Value = j.[value]
        ORDER BY v.RiskScore DESC;
        """, (json.dumps(cleaned),))
    found = {m["Asked"].lower() for m in matches}
    return {"asked": len(cleaned), "matches": matches, "unknown": [v for v in cleaned if v.lower() not in found]}


@router.get("/{indicator_id}")
def get_indicator(indicator_id: int, db: Db = Depends(get_db)):
    ind = db.one("SELECT * FROM dbo.vw_Indicator WHERE IndicatorID = ?;", (indicator_id,))
    if not ind:
        raise HTTPException(404, "Gösterge bulunamadı.")
    ind["Tags"] = [r["Name"] for r in db.query(
        "SELECT tg.Name FROM dbo.IndicatorTag AS it JOIN dbo.Tag AS tg ON tg.TagID = it.TagID WHERE it.IndicatorID = ? ORDER BY tg.Name;",
        (indicator_id,))]
    attribution = db.query(
        """
        -- Atıf zinciri: gösterge -> (zararlı | kampanya) -> aktör
        SELECT a.ViaType, a.ViaID, a.ViaName, a.ActorID, a.ActorName, mi.Role
        FROM dbo.vw_IndicatorAttribution AS a
        LEFT JOIN dbo.MalwareIndicator AS mi
               ON a.ViaType = 'malware' AND mi.MalwareID = a.ViaID AND mi.IndicatorID = a.IndicatorID
        WHERE a.IndicatorID = ?
        ORDER BY a.ViaType DESC, a.ViaName, a.ActorName;
        """, (indicator_id,))
    sightings = db.query(
        """
        SELECT TOP (50) s.SightingID, s.SightedAt, s.Quantity, s.Location, s.Note, u.FullName AS ReportedBy
        FROM dbo.Sighting AS s
        LEFT JOIN dbo.AppUser AS u ON u.UserID = s.ReportedBy
        WHERE s.IndicatorID = ?
        ORDER BY s.SightedAt DESC;
        """, (indicator_id,))
    related = db.query(
        """
        -- Aynı zararlı yazılıma bağlı diğer göstergeler ("bunu gördüysen şunlara da bak")
        SELECT TOP (8) v.IndicatorID, v.Value, v.TypeCode, v.RiskScore, m.Name AS MalwareName
        FROM dbo.MalwareIndicator AS mine
        JOIN dbo.MalwareIndicator AS other ON other.MalwareID = mine.MalwareID AND other.IndicatorID <> mine.IndicatorID
        JOIN dbo.Malware AS m ON m.MalwareID = mine.MalwareID
        JOIN dbo.vw_Indicator AS v ON v.IndicatorID = other.IndicatorID
        WHERE mine.IndicatorID = ? AND v.IsActive = 1
        ORDER BY v.RiskScore DESC;
        """, (indicator_id,))
    history = db.query(
        """
        SELECT TOP (30) l.AuditID, l.Action, l.ChangedAt, l.OldValues, l.NewValues, u.FullName AS ChangedBy
        FROM dbo.AuditLog AS l
        LEFT JOIN dbo.AppUser AS u ON u.UserID = l.ChangedBy
        WHERE l.TableName = N'Indicator' AND l.RecordID = ?
        ORDER BY l.ChangedAt DESC;
        """, (indicator_id,))
    for h in history:
        h["OldValues"] = json.loads(h["OldValues"]) if h["OldValues"] else None
        h["NewValues"] = json.loads(h["NewValues"]) if h["NewValues"] else None
    return {"indicator": ind, "attribution": attribution, "sightings": sightings, "related": related, "history": history}


class IndicatorIn(BaseModel):
    type: str
    value: str = Field(min_length=1, max_length=400)
    confidence: int = Field(ge=0, le=100)
    severity: str
    tlp: str
    sourceId: int
    description: str | None = Field(None, max_length=1000)
    expiresAt: str | None = None
    isActive: bool = True
    tags: list[str] = []


def _save(db: Db, indicator_id: int | None, body: IndicatorIn, user: dict) -> dict:
    row = db.one(
        """
        EXEC dbo.sp_SaveIndicator @IndicatorID = ?, @TypeCode = ?, @Value = ?, @Confidence = ?, @SeverityCode = ?,
             @TLPCode = ?, @SourceID = ?, @Description = ?, @ExpiresAt = ?, @IsActive = ?, @TagsJson = ?, @UserID = ?;
        """,
        (indicator_id, body.type, body.value, body.confidence, body.severity, body.tlp, body.sourceId,
         body.description or None, body.expiresAt or None, int(body.isActive), json.dumps(body.tags), user["UserID"]))
    return {"IndicatorID": row["IndicatorID"]}


@router.post("")
def create_indicator(body: IndicatorIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    return _save(db, None, body, user)


@router.put("/{indicator_id}")
def update_indicator(indicator_id: int, body: IndicatorIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    return _save(db, indicator_id, body, user)


@router.delete("/{indicator_id}")
def delete_indicator(indicator_id: int, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    # Görülmeler, etiketler ve ilişkiler ON DELETE CASCADE ile birlikte silinir
    if not db.execute("DELETE FROM dbo.Indicator WHERE IndicatorID = ?;", (indicator_id,)):
        raise HTTPException(404, "Gösterge bulunamadı.")
    return {"ok": True}


class SightingIn(BaseModel):
    quantity: int = Field(1, ge=1, le=1_000_000)
    location: str | None = Field(None, max_length=100)
    note: str | None = Field(None, max_length=400)


@router.post("/{indicator_id}/sightings")
def add_sighting(indicator_id: int, body: SightingIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    return db.one(
        "EXEC dbo.sp_AddSighting @IndicatorID = ?, @Quantity = ?, @Location = ?, @Note = ?, @SightedAt = NULL, @UserID = ?;",
        (indicator_id, body.quantity, body.location or None, body.note or None, user["UserID"]))
