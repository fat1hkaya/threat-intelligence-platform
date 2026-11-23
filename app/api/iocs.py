"""IOC (gösterge) uçları: listeleme/filtreleme, ekleme, güncelleme, detay, ilişkiler (SQL Graph), görülme kaydı."""
import json
from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .facets import facet_counts
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


def _csv(v: str) -> list[str]:
    """Çoklu seçim: virgülle ayrılmış değerler (boşlar atılır)."""
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def _in(col: str, values: list) -> str:
    return f"{col} IN ({','.join('?' * len(values))})"


def _ioc_conds(q: str, type: str, severity: str, source: str, status: str, malware: int | None, tag: str,
               minConfidence: int, maxConfidence: int, dateFrom: date | None, dateTo: date | None,
               minRisk: int = 0, maxRisk: int = 100, sighted: bool = False, expiring: int = 0, hours: int = 0) -> list[tuple[str, str, list]]:
    """IOC koşulları boyutlarıyla: [(boyut, koşul, parametreler)]. Filtre paneli sayıları bir boyutun kendi koşulunu dışarıda
    bırakır (diğer etkin filtreler uygulanır). Koşullar sabit parçalardan kurulur; kullanıcı girdisi yalnızca parametre (?)."""
    out: list[tuple[str, str, list]] = []
    if q.strip():
        term = _search_term(q).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("[", "\\[")
        out.append(("q", "v.Value LIKE ? ESCAPE '\\'", [f"%{term}%"]))
    if _csv(type):
        out.append(("type", _in("v.TypeCode", _csv(type)), _csv(type)))
    if _csv(severity):
        out.append(("severity", _in("v.SeverityCode", _csv(severity)), _csv(severity)))
    sources = [int(x) for x in _csv(str(source or "")) if x.isdigit()]
    if sources:
        out.append(("source", _in("v.SourceID", sources), sources))
    if _csv(status):
        out.append(("status", _in("v.Status", _csv(status)), _csv(status)))
    if minConfidence > 0 or maxConfidence < 100:
        out.append(("confidence", "v.Confidence BETWEEN ? AND ?", [minConfidence, maxConfidence]))
    if minRisk > 0 or maxRisk < 100:
        out.append(("risk", "v.RiskScore BETWEEN ? AND ?", [minRisk, maxRisk]))
    if hours:                                     # "Son 24 saat": saat tabanlı aralık
        out.append(("date", "v.LastSeen >= DATEADD(HOUR, -?, SYSUTCDATETIME())", [hours]))
    if dateFrom:
        out.append(("date", "v.LastSeen >= ?", [dateFrom]))
    if dateTo:
        out.append(("date", "v.LastSeen < DATEADD(DAY, 1, CAST(? AS DATE))", [dateTo]))
    if malware:
        out.append(("malware", "EXISTS (SELECT 1 FROM dbo.MalwareIndicator AS mi WHERE mi.IndicatorID = v.IndicatorID AND mi.MalwareID = ?)", [malware]))
    if tag:
        out.append(("tag", """EXISTS (SELECT 1 FROM dbo.IndicatorTag AS it JOIN dbo.Tag AS tg ON tg.TagID = it.TagID
                    WHERE it.IndicatorID = v.IndicatorID AND tg.Name = ?)""", [tag]))
    if sighted:                                   # kayıtlı görünüm: kurumda görülenler
        out.append(("sighted", "EXISTS (SELECT 1 FROM dbo.Sighting AS g WHERE g.IndicatorID = v.IndicatorID)", []))
    if expiring:                                  # kayıtlı görünüm: süresi N gün içinde dolacak aktif IOC'ler
        out.append(("expiring", "v.Status = 'active' AND v.ExpiresAt >= SYSUTCDATETIME() AND v.ExpiresAt < DATEADD(DAY, ?, SYSUTCDATETIME())", [expiring]))
    return out


def _join(conds: list[tuple[str, str, list]], skip: str = "") -> tuple[str, list]:
    use = [c for c in conds if c[0] != skip]
    return ("\n          AND ".join(["1 = 1"] + [c[1] for c in use]), [x for c in use for x in c[2]])


def _ioc_filter(*args, **kw) -> tuple[str, list]:
    """IOC listesi ve dışa aktarma için ortak WHERE koşulu."""
    return _join(_ioc_conds(*args, **kw))


@router.get("")
def list_iocs(
    q: str = Query("", max_length=400), type: str = "", severity: str = "", source: str = "",
    status: str = "", malware: int | None = None, tag: str = "",
    minConfidence: int = Query(0, ge=0, le=100), maxConfidence: int = Query(100, ge=0, le=100),
    dateFrom: date | None = None, dateTo: date | None = None,
    minRisk: int = Query(0, ge=0, le=100), maxRisk: int = Query(100, ge=0, le=100),
    sighted: bool = False, expiring: int = Query(0, ge=0, le=365), hours: int = Query(0, ge=0, le=720),
    sort: str = "lastSeen", dir: str = "desc", page: int = Query(1, ge=1), size: int = Query(25, ge=5, le=200),
    db: Db = Depends(get_db),
):
    clause, params = _ioc_filter(q, type, severity, source, status, malware, tag, minConfidence, maxConfidence, dateFrom, dateTo,
                                 minRisk, maxRisk, sighted, expiring, hours)
    order = f"{SORTS.get(sort, 'v.LastSeen')} {'ASC' if dir == 'asc' else 'DESC'}, v.IndicatorID DESC"

    total = db.scalar(f"SELECT COUNT(*) AS Total FROM dbo.vw_Indicator AS v\n        WHERE {clause};", tuple(params))
    items = db.query(
        f"""
        SELECT v.IndicatorID, v.Value, v.TypeCode, v.TypeName, v.Confidence, v.SeverityCode, v.SeverityName, v.TLPCode,
               v.SourceID, v.SourceName, v.FirstSeen, v.LastSeen, v.Status, v.SightingCount, v.RiskScore,
               (SELECT TOP (1) dbo.fn_MalwareLabel(m.Name, m.ExternalID) FROM dbo.MalwareIndicator AS mi JOIN dbo.Malware AS m ON m.MalwareID = mi.MalwareID
                 WHERE mi.IndicatorID = v.IndicatorID ORDER BY m.IsPlaceholder, mi.Confidence DESC, m.Name) AS MalwareName,
               (SELECT TOP (1) a.Name FROM dbo.MalwareIndicator AS mi JOIN dbo.ActorMalware AS am ON am.MalwareID = mi.MalwareID
                       JOIN dbo.ThreatActor AS a ON a.ActorID = am.ActorID
                 WHERE mi.IndicatorID = v.IndicatorID ORDER BY am.Confidence DESC, a.Name) AS ActorName
        FROM dbo.vw_Indicator AS v
        WHERE {clause}
        ORDER BY {order}
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;      -- sayfalama
        """, tuple(params) + ((page - 1) * size, size))
    return {"items": items, "total": total, "page": page, "size": size}


FACETS = {"type": "v.TypeCode", "severity": "v.SeverityCode", "source": "v.SourceID", "status": "v.Status"}


@router.get("/facets")
def ioc_facets(
    q: str = Query("", max_length=400), type: str = "", severity: str = "", source: str = "",
    status: str = "", malware: int | None = None, tag: str = "",
    minConfidence: int = Query(0, ge=0, le=100), maxConfidence: int = Query(100, ge=0, le=100),
    dateFrom: date | None = None, dateTo: date | None = None,
    minRisk: int = Query(0, ge=0, le=100), maxRisk: int = Query(100, ge=0, le=100),
    sighted: bool = False, expiring: int = Query(0, ge=0, le=365), hours: int = Query(0, ge=0, le=720), db: Db = Depends(get_db),
):
    """Filtre paneli sayıları: her boyut için GROUP BY; sayım diğer etkin filtreleri uygular, kendi boyutunu uygulamaz."""
    conds = _ioc_conds(q, type, severity, source, status, malware, tag, minConfidence, maxConfidence, dateFrom, dateTo,
                       minRisk, maxRisk, sighted, expiring, hours)
    return facet_counts(db, "dbo.vw_Indicator AS v", conds, FACETS)


@router.get("/views")
def ioc_views(db: Db = Depends(get_db)):
    """Kayıtlı görünümlerin sayıları (tek satırda skaler alt sorgular)."""
    return db.one(
        """
        DECLARE @now DATETIME2(0) = SYSUTCDATETIME();
        SELECT (SELECT COUNT(*) FROM dbo.Indicator) AS [all],
               (SELECT COUNT(*) FROM dbo.Indicator AS i JOIN dbo.SeverityLevel AS s ON s.SeverityID = i.SeverityID
                 WHERE i.Status = 'active' AND s.Code IN ('high', 'critical') AND i.LastSeen >= DATEADD(HOUR, -24, @now)) AS high24h,
               (SELECT COUNT(DISTINCT IndicatorID) FROM dbo.Sighting) AS sighted,
               (SELECT COUNT(*) FROM dbo.Indicator WHERE Status = 'active' AND ExpiresAt >= @now AND ExpiresAt < DATEADD(DAY, 7, @now)) AS expiring;
        """)


EXPORT_LIMIT = 50000


def _csv_cell(v) -> str:
    """CSV/formül enjeksiyonuna karşı: =, +, -, @ ile başlayan hücreler tek tırnakla etkisizleştirilir."""
    text = "" if v is None else str(v)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@router.get("/export")
def export_iocs(
    format: str = Query("csv", pattern="^(csv|txt)$"),
    q: str = Query("", max_length=400), type: str = "", severity: str = "", source: str = "",
    status: str = "", malware: int | None = None, tag: str = "",
    minConfidence: int = Query(0, ge=0, le=100), maxConfidence: int = Query(100, ge=0, le=100),
    dateFrom: date | None = None, dateTo: date | None = None,
    minRisk: int = Query(0, ge=0, le=100), maxRisk: int = Query(100, ge=0, le=100),
    sighted: bool = False, expiring: int = Query(0, ge=0, le=365), hours: int = Query(0, ge=0, le=720),
    ids: str = Query("", max_length=20000, description="Virgülle IOC kimlikleri: yalnızca seçili satırlar"),
    db: Db = Depends(get_db),
):
    """Ekrandaki filtrelerle eşleşen IOC'ler (en çok 50.000). csv: tüm sütunlar; txt: satır başına bir değer
    (güvenlik duvarı / proxy engelleme listesi için). ids verilirse filtreler yerine yalnızca o kayıtlar."""
    import csv
    import io

    from fastapi.responses import Response

    if ids.strip():
        try:
            id_list = [int(x) for x in ids.split(",") if x.strip()][:1000]
        except ValueError as exc:
            raise HTTPException(400, "Kimlik listesi yalnızca sayı içermeli.") from exc
        clause, params = "v.IndicatorID IN (SELECT CAST([value] AS BIGINT) FROM OPENJSON(?))", [json.dumps(id_list)]
    else:
        clause, params = _ioc_filter(q, type, severity, source, status, malware, tag, minConfidence, maxConfidence,
                                     dateFrom, dateTo, minRisk, maxRisk, sighted, expiring, hours)
    rows = db.query(
        f"""
        SELECT TOP ({EXPORT_LIMIT}) v.Value, v.TypeCode, v.SeverityCode, v.Confidence, v.RiskScore, v.Status, v.TLPCode,
               v.SourceName, v.FirstSeen, v.LastSeen, v.ExpiresAt,
               (SELECT TOP (1) m.Name FROM dbo.MalwareIndicator AS mi JOIN dbo.Malware AS m ON m.MalwareID = mi.MalwareID
                 WHERE mi.IndicatorID = v.IndicatorID ORDER BY mi.Confidence DESC, m.Name) AS Malware
        FROM dbo.vw_Indicator AS v
        WHERE {clause}
        ORDER BY v.RiskScore DESC, v.LastSeen DESC;
        """, tuple(params))
    stamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M")
    if format == "txt":
        body = "\n".join(r["Value"] for r in rows) + ("\n" if rows else "")
        return Response(body, media_type="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="threatlens_ioc_{stamp}.txt"'})
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["Value", "TypeCode", "SeverityCode", "Confidence", "RiskScore", "Status", "TLPCode", "SourceName", "Malware",
            "FirstSeen", "LastSeen", "ExpiresAt"]
    w.writerow(["deger", "tip", "onem", "guven", "risk", "durum", "tlp", "kaynak", "zararli", "ilk_gorulme", "son_gorulme", "gecerlilik_sonu"])
    for r in rows:
        w.writerow([_csv_cell(r[c]) for c in cols])
    # Excel'in Türkçe karakterleri doğru açması için UTF-8 BOM
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="threatlens_ioc_{stamp}.csv"'})


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


@router.get("/check")
def check_value(value: str = Query(..., min_length=1, max_length=400), type: str = "", db: Db = Depends(get_db)):
    """Yeni IOC formunun canlı önizlemesi: algılanan tip, kaydedilecek (normalleştirilmiş) değer, biçim hatası
    ve aynı göstergenin zaten kayıtlı olup olmadığı. Kayıt yazmaz."""
    type_code = type.strip().lower() or guess_type(value)
    if not type_code:
        return {"type": None, "normalized": None, "error": "Tip algılanamadı; tipi elle seçin.", "existing": None}
    try:
        normalized = normalize(type_code, value)
    except InvalidIndicator as exc:
        return {"type": type_code, "normalized": None, "error": str(exc), "existing": None}
    existing = db.one(
        """SELECT TOP (1) i.IndicatorID, i.Value FROM dbo.Indicator AS i JOIN dbo.IndicatorType AS t ON t.TypeID = i.TypeID
           WHERE t.Code = ? AND i.NormalizedValue = ?;""", (type_code, normalized))
    return {"type": type_code, "normalized": normalized, "error": None, "existing": existing}


class BulkStatus(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=500)
    status: str = Field(pattern="^(active|expired|revoked|false_positive)$")


@router.post("/bulk-status")
def bulk_status(body: BulkStatus, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    """Seçili IOC'lerin durumunu tek UPDATE ile değiştirir. Denetim tetikleyicisi her satırı ayrı kaydeder."""
    n = db.execute(
        """
        UPDATE i SET Status = ?, UpdatedAt = SYSUTCDATETIME()
        FROM dbo.Indicator AS i
        JOIN OPENJSON(?) AS j ON CAST(j.[value] AS BIGINT) = i.IndicatorID
        WHERE i.Status <> ?;
        """, (body.status, json.dumps(body.ids), body.status))
    return {"updated": max(n, 0)}


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
        SELECT TOP (8) v.IndicatorID, v.Value, v.TypeCode, v.SeverityCode, v.RiskScore, dbo.fn_MalwareLabel(m.Name, m.ExternalID) AS MalwareName
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
    risk = db.one(
        """
        -- Skorun bileşenleri: görünümle aynı formül (satır içi fn_RiskBreakdown)
        SELECT rb.ConfidencePart, rb.SeverityPart, rb.SightingPart, rb.BasePoints, rb.ReliabilityFactor,
               rb.AgeDays, rb.FreshnessFactor, rb.StatusFactor, rb.Score, sv.Weight AS SeverityWeight
        FROM dbo.Indicator AS i
        JOIN dbo.SeverityLevel AS sv ON sv.SeverityID = i.SeverityID
        JOIN dbo.Source AS s ON s.SourceID = i.SourceID
        OUTER APPLY (SELECT SUM(Quantity) AS N FROM dbo.Sighting AS g WHERE g.IndicatorID = i.IndicatorID) AS sc
        CROSS APPLY dbo.fn_RiskBreakdown(i.Confidence, sv.Weight, i.LastSeen, sc.N, s.Reliability,
                                         CASE WHEN i.Status = 'active' THEN 1 ELSE 0 END, SYSUTCDATETIME()) AS rb
        WHERE i.IndicatorID = ?;
        """, (indicator_id,))
    return {"indicator": ind, "sightings": sightings, "related": related, "history": history, "risk": risk}


@router.get("/{indicator_id}/relationships")
def ioc_relationships(indicator_id: int, db: Db = Depends(get_db)):
    """Göstergenin ilişkileri SQL Graph üzerinden: MATCH tabanlı vw_IndicatorAttribution ve çok adımlı
    MATCH kullanan sp_IndicatorKillChain (gösterge -> zararlı <- aktör -> teknik)."""
    if not db.scalar("SELECT COUNT(*) AS N FROM dbo.IndicatorNode WHERE IndicatorID = ?;", (indicator_id,)):
        raise HTTPException(404, "Gösterge graf düğümü bulunamadı.")
    attribution = db.query(
        """
        -- Zincirin her halkasının kanıtı: IOC -> zararlı/kampanya (kenar) ve zararlı/kampanya -> aktör (ilişki tablosu)
        SELECT a.ViaType, a.ViaID, a.ViaName, a.Role, a.Confidence, a.EvidenceID, a.ActorID, a.ActorName,
               e.Summary AS Evidence, s.Name AS EvidenceSource,
               COALESCE(am.Confidence, NULL) AS ActorConfidence, e2.Summary AS ActorEvidence, s2.Name AS ActorEvidenceSource
        FROM dbo.vw_IndicatorAttribution AS a               -- görünüm içinde MATCH(i-(e)->m) ve MATCH(c-(e)->i)
        LEFT JOIN dbo.Evidence AS e ON e.EvidenceID = a.EvidenceID
        LEFT JOIN dbo.Source AS s ON s.SourceID = e.SourceID
        LEFT JOIN dbo.ActorMalware AS am ON a.ViaType = 'malware' AND am.ActorID = a.ActorID AND am.MalwareID = a.ViaID
        LEFT JOIN dbo.Campaign AS ca ON a.ViaType = 'campaign' AND ca.CampaignID = a.ViaID
        LEFT JOIN dbo.Evidence AS e2 ON e2.EvidenceID = COALESCE(am.EvidenceID, ca.AttributionEvidenceID)
        LEFT JOIN dbo.Source AS s2 ON s2.SourceID = e2.SourceID
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


@router.get("/{indicator_id}/versions")
def ioc_versions(indicator_id: int, db: Db = Depends(get_db)):
    """Sistem sürümlü tablodan tüm sürümler (FOR SYSTEM_TIME ALL)."""
    rows = db.query("EXEC dbo.sp_IndicatorVersions @IndicatorID = ?;", (indicator_id,))
    if not rows:
        raise HTTPException(404, "Gösterge bulunamadı.")
    return rows


@router.get("/{indicator_id}/asof")
def ioc_as_of(indicator_id: int, at: datetime, db: Db = Depends(get_db)):
    """IOC'nin belirli bir andaki hâli ve o andaki zararlı ilişkileri (FOR SYSTEM_TIME AS OF). 'at' UTC olarak yorumlanır."""
    if at.tzinfo is not None:
        at = at.astimezone(timezone.utc).replace(tzinfo=None)
    state, links = (db.query_sets("EXEC dbo.sp_IndicatorAsOf @IndicatorID = ?, @AsOf = ?;", (indicator_id, at)) + [[], []])[:2]
    return {"at": at, "state": state[0] if state else None, "malware": links}


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
