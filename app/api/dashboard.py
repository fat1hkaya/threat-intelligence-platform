"""Genel bakış (dashboard), sözlükler, global arama ve SQL izi uçları.
Ekrandaki her sayı aşağıdaki sorgulardan gelir; sabit/uydurma değer yoktur."""
from fastapi import APIRouter, Depends, HTTPException, Query

from ..db import TRACES, Db, get_db
from ..security import current_user

router = APIRouter(prefix="/api", tags=["dashboard"], dependencies=[Depends(current_user)])


@router.get("/meta")
def meta(db: Db = Depends(get_db)):
    """Form ve filtrelerde kullanılan sözlük tabloları."""
    return {
        "types": db.query("SELECT TypeID, Code, Name FROM dbo.IndicatorType ORDER BY TypeID;", trace=False),
        "severities": db.query("SELECT SeverityID, Code, Name, Weight FROM dbo.SeverityLevel ORDER BY SeverityID;", trace=False),
        "tlps": db.query("SELECT TLPID, Code, Description FROM dbo.TLPLevel ORDER BY TLPID;", trace=False),
        "sources": db.query("SELECT SourceID, Name, Reliability FROM dbo.Source WHERE IsActive = 1 ORDER BY Name;", trace=False),
        "motivations": db.query("SELECT MotivationID, Name FROM dbo.Motivation ORDER BY MotivationID;", trace=False),
        "malwareTypes": db.query("SELECT MalwareTypeID, Code, Name FROM dbo.MalwareType ORDER BY Name;", trace=False),
        "countries": db.query("SELECT CountryCode, Name FROM dbo.Country ORDER BY Name;", trace=False),
        "sectors": db.query("SELECT SectorID, Name FROM dbo.Sector ORDER BY Name;", trace=False),
        "tactics": db.query("SELECT TacticID, ExternalID, Name, ShortName FROM dbo.Tactic ORDER BY DisplayOrder;", trace=False),
    }


@router.get("/dashboard/summary")
def dashboard_summary(days: int = Query(30, ge=7, le=180), db: Db = Depends(get_db)):
    kpi = db.one(
        """
        -- KPI kartları: skaler alt sorgular tek satırda. Değişim, son N gün ile ondan önceki N günün karşılaştırmasıdır.
        DECLARE @now DATETIME2(0) = SYSUTCDATETIME();
        DECLARE @d INT = ?;
        DECLARE @start DATETIME2(0) = CAST(CAST(DATEADD(DAY, 1 - @d, @now) AS DATE) AS DATETIME2(0));   -- son @d takvim günü
        SELECT
            (SELECT COUNT(*) FROM dbo.Indicator)                                         AS TotalIOCs,
            (SELECT COUNT(*) FROM dbo.Indicator WHERE Status = 'active')                 AS ActiveIOCs,
            (SELECT COUNT(*) FROM dbo.Indicator WHERE FirstSeen >= @start)                AS NewIOCs,
            (SELECT COUNT(*) FROM dbo.Indicator WHERE FirstSeen >= DATEADD(DAY, -@d, @start)
                                                  AND FirstSeen <  @start)               AS PrevNewIOCs,
            (SELECT COUNT(*) FROM dbo.ThreatActor)                                       AS Actors,
            (SELECT COUNT(DISTINCT ActorID) FROM dbo.vw_IndicatorAttribution WHERE ActorID IS NOT NULL) AS ActorsWithIOCs,
            (SELECT COUNT(*) FROM dbo.Malware AS m JOIN dbo.MalwareType AS t ON t.MalwareTypeID = m.MalwareTypeID
              WHERE t.Code <> 'tool')                                                    AS MalwareFamilies,
            (SELECT COUNT(DISTINCT MalwareID) FROM dbo.MalwareIndicator)                 AS FamiliesWithIOCs,
            (SELECT COUNT(*) FROM dbo.Indicator AS i JOIN dbo.SeverityLevel AS s ON s.SeverityID = i.SeverityID
              WHERE i.Status = 'active' AND s.Code IN ('high', 'critical'))              AS HighRiskIOCs,
            (SELECT COUNT(*) FROM dbo.Indicator AS i JOIN dbo.SeverityLevel AS s ON s.SeverityID = i.SeverityID
              WHERE i.Status = 'active' AND s.Code IN ('high', 'critical')
                AND i.FirstSeen >= @start)                                               AS NewHighRiskIOCs,
            (SELECT COUNT(*) FROM dbo.Campaign)                                          AS Campaigns,
            (SELECT COUNT(*) FROM dbo.Technique)                                         AS Techniques,
            (SELECT ISNULL(SUM(Quantity), 0) FROM dbo.Sighting WHERE SightedAt >= DATEADD(DAY, -7, @now)) AS Sightings7d;
        """, (days,))
    by_severity = db.query(
        """
        SELECT s.Code, s.Name, COUNT(i.IndicatorID) AS Total
        FROM dbo.SeverityLevel AS s
        LEFT JOIN dbo.Indicator AS i ON i.SeverityID = s.SeverityID AND i.Status = 'active'
        GROUP BY s.SeverityID, s.Code, s.Name
        ORDER BY s.SeverityID DESC;
        """)
    by_type = db.query(
        """
        SELECT t.Code, t.Name, COUNT(i.IndicatorID) AS Total
        FROM dbo.IndicatorType AS t
        LEFT JOIN dbo.Indicator AS i ON i.TypeID = t.TypeID AND i.Status = 'active'
        GROUP BY t.TypeID, t.Code, t.Name
        HAVING COUNT(i.IndicatorID) > 0
        ORDER BY Total DESC;
        """)
    trend = db.query(
        """
        -- Son N gün: özyinelemeli CTE ile takvim üretilir, kayıt olmayan günler 0 görünür
        WITH days AS (
            SELECT CAST(DATEADD(DAY, 1 - ?, SYSUTCDATETIME()) AS DATE) AS [Day]
            UNION ALL
            SELECT DATEADD(DAY, 1, [Day]) FROM days WHERE [Day] < CAST(SYSUTCDATETIME() AS DATE)
        ),
        added AS (
            SELECT CAST(FirstSeen AS DATE) AS [Day], COUNT(*) AS Added
            FROM dbo.Indicator
            WHERE FirstSeen >= DATEADD(DAY, -?, CAST(SYSUTCDATETIME() AS DATE))
            GROUP BY CAST(FirstSeen AS DATE)
        )
        SELECT d.[Day], ISNULL(a.Added, 0) AS Added
        FROM days AS d LEFT JOIN added AS a ON a.[Day] = d.[Day]
        ORDER BY d.[Day]
        OPTION (MAXRECURSION 200);
        """, (days, days))
    latest = db.query(
        """
        -- Son istihbarat: en son görülen göstergeler, atıf zinciriyle (MATCH tabanlı görünüm)
        SELECT TOP (8) v.IndicatorID, v.Value, v.TypeCode, v.SeverityCode, v.SeverityName, v.Confidence, v.SourceName, v.LastSeen,
               (SELECT TOP (1) a.ViaName FROM dbo.vw_IndicatorAttribution AS a
                 WHERE a.IndicatorID = v.IndicatorID AND a.ViaType = 'malware') AS MalwareName,
               (SELECT TOP (1) a.ViaName FROM dbo.vw_IndicatorAttribution AS a
                 WHERE a.IndicatorID = v.IndicatorID AND a.ViaType = 'campaign') AS CampaignName
        FROM dbo.vw_Indicator AS v
        ORDER BY v.LastSeen DESC, v.IndicatorID DESC;
        """)
    sources = db.query(
        """
        SELECT SourceID, Name, Reliability, IndicatorCount, EvidenceCount, LastJobID, LastRunAt, LastRunStatus,
               LastRowsInserted, LastRowsUpdated, LastRowsFailed
        FROM dbo.vw_SourceHealth
        WHERE IsActive = 1
        ORDER BY CASE WHEN LastRunAt IS NULL THEN 1 ELSE 0 END, LastRunAt DESC, Name;
        """)
    top_techniques = db.query(
        """
        -- En çok aktör tarafından kullanılan ATT&CK teknikleri (alt teknikler üst tekniğe toplanır)
        SELECT TOP (6) t.TechniqueID, t.ExternalID, t.Name, COUNT(DISTINCT x.ActorID) AS ActorCount
        FROM dbo.ActorTechnique AS x
        JOIN dbo.Technique AS st ON st.TechniqueID = x.TechniqueID
        JOIN dbo.Technique AS t ON t.TechniqueID = COALESCE(st.ParentTechniqueID, st.TechniqueID)
        GROUP BY t.TechniqueID, t.ExternalID, t.Name
        ORDER BY ActorCount DESC, t.ExternalID;
        """)
    top_malware = db.query(
        """
        SELECT TOP (6) m.MalwareID, m.Name, m.TypeName, m.IndicatorCount
        FROM dbo.vw_MalwareSummary AS m
        WHERE m.IndicatorCount > 0
        ORDER BY m.IndicatorCount DESC, m.Name;
        """)
    return {"kpi": kpi, "bySeverity": by_severity, "byType": by_type, "trend": trend, "latest": latest,
            "sources": sources, "topTechniques": top_techniques, "topMalware": top_malware, "days": days}


@router.get("/search")
def global_search(q: str = Query("", max_length=200), db: Db = Depends(get_db)):
    """Üst bardaki global arama: sp_GlobalSearch (IOC, aktör, zararlı, kampanya, teknik, CVE)."""
    if len(q.strip()) < 2:
        return []
    from ..services.normalize import InvalidIndicator, guess_type, normalize

    term = q.strip()
    kind = guess_type(term)
    if kind:  # yapıştırılan IOC (ör. hxxp://evil[.]com) önce kanonik biçime çevrilir
        try:
            term = normalize(kind, term)
        except InvalidIndicator:
            pass
    return db.query("EXEC dbo.sp_GlobalSearch @Query = ?, @Top = ?;", (term, 6))


@router.get("/trace/{trace_id}")
def trace(trace_id: str):
    """Arayüzdeki 'SQL' çekmecesi: bir isteğin çalıştırdığı gerçek T-SQL ifadeleri."""
    item = TRACES.get(trace_id)
    if not item:
        raise HTTPException(404, "Sorgu izi bulunamadı (bellekten düşmüş olabilir).")
    return item
