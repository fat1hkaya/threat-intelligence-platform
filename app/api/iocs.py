"""IOC (gösterge) uçları: listeleme/filtreleme, ekleme, güncelleme, detay, ilişkiler (SQL Graph), görülme kaydı."""
import json
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..db import Db, get_db
from ..security import current_user, require_analyst
from ..services.normalize import InvalidIndicator, guess_type, normalize

router = APIRouter(prefix="/api/iocs", tags=["iocs"], dependencies=[Depends(current_user)])

# Sıralama sütunları izinli listeden gelir; kullanıcı girdisi SQL'e doğrudan yazılmaz
SORTS = {"lastSeen": "v.LastSeen", "firstSeen": "v.FirstSeen", "confidence": "v.Confidence", "risk": "v.RiskScore",
         "severity": "v.SeverityID", "value": "v.Value", "type": "v.TypeCode", "source": "v.SourceName"}


def _search_term(q: str) -> str:
    """Yapıştırılan değer IOC'ye benziyorsa kanonik biçime çevrilir (hxxp://evil[.]com -> http://evil.com/)."""
    term = q.strip()
    kind = guess_type(term)
    if kind:
        try:
            return normalize(kind, term)
        except InvalidIndicator:
            pass
    return term.lower()


@router.get("")
def list_iocs(
    q: str = Query("", max_length=400), type: str = "", severity: str = "", source: int | None = None,
    status: str = "", malware: int | None = None, tag: str = "",
    minConfidence: int = Query(0, ge=0, le=100), maxConfidence: int = Query(100, ge=0, le=100),
    dateFrom: date | None = None, dateTo: date | None = None,
    sort: str = "lastSeen", dir: str = "desc", page: int = Query(1, ge=1), size: int = Query(25, ge=5, le=200),
    db: Db = Depends(get_db),
):
    # WHERE koşulları sabit parçalardan kurulur; kullanıcı girdisi yalnızca parametre (?) olarak geçer
    where, params = ["1 = 1"], []
    if q.strip():
        where.append("v.Value LIKE ? ESCAPE '\\'")
        term = _search_term(q).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("[", "\\[")
        params.append(f"%{term}%")
    if type:
        where.append("v.TypeCode = ?"); params.append(type)
    if severity:
        sev = [s for s in severity.split(",") if s]
        where.append(f"v.SeverityCode IN ({','.join('?' * len(sev))})"); params += sev
    if source:
        where.append("v.SourceID = ?"); params.append(source)
    if status:
        where.append("v.Status = ?"); params.append(status)
    if minConfidence > 0 or maxConfidence < 100:
        where.append("v.Confidence BETWEEN ? AND ?"); params += [minConfidence, maxConfidence]
    if dateFrom:
        where.append("v.LastSeen >= ?"); params.append(dateFrom)
    if dateTo:
        where.append("v.LastSeen < DATEADD(DAY, 1, CAST(? AS DATE))"); params.append(dateTo)
    if malware:
        where.append("EXISTS (SELECT 1 FROM dbo.MalwareIndicator AS mi WHERE mi.IndicatorID = v.IndicatorID AND mi.MalwareID = ?)")
        params.append(malware)
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
               v.SourceID, v.SourceName, v.FirstSeen, v.LastSeen, v.Status, v.SightingCount, v.RiskScore,
               (SELECT TOP (1) m.Name FROM dbo.MalwareIndicator AS mi JOIN dbo.Malware AS m ON m.MalwareID = mi.MalwareID
                 WHERE mi.IndicatorID = v.IndicatorID ORDER BY mi.Confidence DESC, m.Name) AS MalwareName
        FROM dbo.vw_Indicator AS v
        WHERE {clause}
        ORDER BY {order}
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;      -- sayfalama
        """, tuple(params) + ((page - 1) * size, size))
    return {"items": items, "total": total, "page": page, "size": size}


class BulkLookup(BaseModel):
    values: list[str] = Field(max_length=2000)


@router.post("/lookup")
def bulk_lookup(body: BulkLookup, db: Db = Depends(get_db)):
    """Yapıştırılan IOC listesinden hangileri kayıtlı? Değerler önce Python'da normalleştirilir."""
    asked: dict[str, str] = {}
    for raw in body.values:
        if raw.strip():
            asked.setdefault(_search_term(raw), raw.strip())
    if not asked:
        return {"asked": 0, "matches": [], "unknown": []}
    matches = db.query(
        """
        -- Liste JSON olarak tek parametrede gelir; OPENJSON ile tabloya açılıp JOIN edilir
        SELECT j.[value] AS Asked, v.IndicatorID, v.Value, v.TypeCode, v.RiskScore, v.SeverityCode, v.Status, v.LastSeen, v.SourceName
        FROM OPENJSON(?) AS j
        JOIN dbo.vw_Indicator AS v ON v.Value = j.[value]
        ORDER BY v.RiskScore DESC;
        """, (json.dumps(list(asked)),))
    found = {m["Asked"] for m in matches}
    return {"asked": len(asked), "matches": matches, "unknown": [asked[k] for k in asked if k not in found]}


@router.get("/examples")
def examples(db: Db = Depends(get_db)):
    """İlişki grafı ekranındaki örnek düğmeleri: atıf zinciri bir aktöre ulaşan gerçek IOC'ler (tip başına en yenisi)."""
    return db.query(
        """
        WITH chain AS (   -- MATCH tabanlı görünüm: IOC -> zararlı -> aktör
            SELECT a.IndicatorID, a.ViaName AS MalwareName, a.ActorName,
                   ROW_NUMBER() OVER (PARTITION BY v.TypeCode ORDER BY v.LastSeen DESC) AS rn, v.TypeCode, v.Value
            FROM dbo.vw_IndicatorAttribution AS a
            JOIN dbo.vw_Indicator AS v ON v.IndicatorID = a.IndicatorID
            WHERE a.ViaType = 'malware' AND a.ActorID IS NOT NULL AND v.TypeCode IN ('sha256', 'ipv4', 'domain')
        )
        SELECT IndicatorID, TypeCode, Value, MalwareName, ActorName FROM chain WHERE rn = 1;
        """)


@router.get("/{indicator_id}")
def get_ioc(indicator_id: int, db: Db = Depends(get_db)):
    ind = db.one("SELECT * FROM dbo.vw_Indicator WHERE IndicatorID = ?;", (indicator_id,))
    if not ind:
        raise HTTPException(404, "Gösterge bulunamadı.")
    ind["Tags"] = [r["Name"] for r in db.query(
        "SELECT tg.Name FROM dbo.IndicatorTag AS it JOIN dbo.Tag AS tg ON tg.TagID = it.TagID WHERE it.IndicatorID = ? ORDER BY tg.Name;",
        (indicator_id,))]
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
        -- Aynı zararlı yazılıma bağlı diğer göstergeler (self join)
        SELECT TOP (8) v.IndicatorID, v.Value, v.TypeCode, v.SeverityCode, v.RiskScore, m.Name AS MalwareName
        FROM dbo.MalwareIndicator AS mine
        JOIN dbo.MalwareIndicator AS other ON other.MalwareID = mine.MalwareID AND other.IndicatorID <> mine.IndicatorID
        JOIN dbo.Malware AS m ON m.MalwareID = mine.MalwareID
        JOIN dbo.vw_Indicator AS v ON v.IndicatorID = other.IndicatorID
        WHERE mine.IndicatorID = ? AND v.Status = 'active'
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
    return {"indicator": ind, "sightings": sightings, "related": related, "history": history}


@router.get("/{indicator_id}/relationships")
def ioc_relationships(indicator_id: int, db: Db = Depends(get_db)):
    """Göstergenin ilişkileri SQL Graph üzerinden: MATCH tabanlı vw_IndicatorAttribution ve çok adımlı
    MATCH kullanan sp_IndicatorKillChain (gösterge -> zararlı <- aktör -> teknik)."""
    if not db.scalar("SELECT COUNT(*) AS N FROM dbo.IndicatorNode WHERE IndicatorID = ?;", (indicator_id,)):
        raise HTTPException(404, "Gösterge graf düğümü bulunamadı.")
    attribution = db.query(
        """
        SELECT a.ViaType, a.ViaID, a.ViaName, a.Role, a.Confidence, a.EvidenceID, a.ActorID, a.ActorName,
               e.Summary AS Evidence, s.Name AS EvidenceSource
        FROM dbo.vw_IndicatorAttribution AS a               -- görünüm içinde MATCH(i-(e)->m) ve MATCH(c-(e)->i)
        LEFT JOIN dbo.Evidence AS e ON e.EvidenceID = a.EvidenceID
        LEFT JOIN dbo.Source AS s ON s.SourceID = e.SourceID
        WHERE a.IndicatorID = ?
        ORDER BY a.ViaType DESC, a.ViaName, a.ActorName;
        """, (indicator_id,))
    killchain = db.query("EXEC dbo.sp_IndicatorKillChain @IndicatorID = ?;", (indicator_id,))
    malware_techniques = db.query(
        """
        -- Gösterge -> zararlı -> teknik: iki kenarlı MATCH deseni
        SELECT DISTINCT TOP (40) m.Name AS Malware, t.ExternalID, t.Name AS Technique
        FROM dbo.IndicatorNode AS i_n, dbo.IndicatesMalware AS e1, dbo.MalwareNode AS m_n,
             dbo.MalwareUsesTechnique AS e2, dbo.TechniqueNode AS t_n,
             dbo.Malware AS m, dbo.Technique AS t
        WHERE MATCH(i_n-(e1)->m_n-(e2)->t_n)
          AND i_n.IndicatorID = ?
          AND m.MalwareID = m_n.MalwareID AND t.TechniqueID = t_n.TechniqueID
        ORDER BY t.ExternalID;
        """, (indicator_id,))
    return {"attribution": attribution, "killchain": killchain, "malwareTechniques": malware_techniques}


class IndicatorIn(BaseModel):
    type: str | None = Field(None, description="Boşsa değerin biçiminden tahmin edilir")
    value: str = Field(min_length=1, max_length=400)
    confidence: int = Field(50, ge=0, le=100)
    severity: str = "medium"
    tlp: str = "TLP:CLEAR"
    sourceId: int
    status: str = "active"
    description: str | None = Field(None, max_length=1000)
    expiresAt: str | None = None
    tags: list[str] = []
    rowVer: str | None = Field(None, description="Güncellemede okunan sürüm (iyimser eşzamanlılık)")


def _save(db: Db, indicator_id: int | None, body: IndicatorIn, user: dict) -> dict:
    type_code = (body.type or "").strip().lower() or guess_type(body.value)
    if not type_code:
        raise HTTPException(400, "Gösterge tipi belirlenemedi; tipi elle seçin.")
    try:
        normalized = normalize(type_code, body.value)
    except InvalidIndicator as exc:
        raise HTTPException(400, str(exc)) from exc
    row = db.one(
        """
        EXEC dbo.sp_SaveIndicator @IndicatorID = ?, @TypeCode = ?, @Value = ?, @NormalizedValue = ?, @Confidence = ?,
             @SeverityCode = ?, @TLPCode = ?, @SourceID = ?, @Status = ?, @Description = ?, @ExpiresAt = ?,
             @TagsJson = ?, @RowVer = ?, @UserID = ?;
        """,
        (indicator_id, type_code, body.value.strip(), normalized, body.confidence, body.severity, body.tlp, body.sourceId,
         body.status, body.description or None, body.expiresAt or None, json.dumps(body.tags), body.rowVer or None,
         user["UserID"]))
    return {"IndicatorID": row["IndicatorID"], "type": type_code, "normalized": normalized}


@router.post("", status_code=201)
def create_ioc(body: IndicatorIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    return _save(db, None, body, user)


@router.put("/{indicator_id}")
def update_ioc(indicator_id: int, body: IndicatorIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    return _save(db, indicator_id, body, user)


@router.delete("/{indicator_id}")
def delete_ioc(indicator_id: int, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    # Görülmeler, etiketler ve ilişkiler ON DELETE CASCADE ile; graf düğümü/kenarları tetikleyiciyle silinir
    if not db.execute("DELETE FROM dbo.Indicator WHERE IndicatorID = ?;", (indicator_id,)):
        raise HTTPException(404, "Gösterge bulunamadı.")
    return {"ok": True}


class SightingIn(BaseModel):
    quantity: int = Field(1, ge=1, le=1_000_000)
    location: str | None = Field(None, max_length=100)
    note: str | None = Field(None, max_length=400)


@router.post("/{indicator_id}/sightings", status_code=201)
def add_sighting(indicator_id: int, body: SightingIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    return db.one(
        "EXEC dbo.sp_AddSighting @IndicatorID = ?, @Quantity = ?, @Location = ?, @Note = ?, @SightedAt = NULL, @UserID = ?;",
        (indicator_id, body.quantity, body.location or None, body.note or None, user["UserID"]))
