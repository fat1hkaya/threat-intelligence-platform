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
        # Filtrelerde yalnızca IOC üreten kaynaklar (CISA KEV, Malpedia, iptoasn.com, ATT&CK IOC üretmez)
        "iocSources": db.query("""SELECT s.SourceID, s.Name FROM dbo.Source AS s
                                  WHERE EXISTS (SELECT 1 FROM dbo.Indicator AS i WHERE i.SourceID = s.SourceID)
                                  ORDER BY s.Name;""", trace=False),
        "motivations": db.query("SELECT MotivationID, Name FROM dbo.Motivation ORDER BY MotivationID;", trace=False),
        "malwareTypes": db.query("SELECT MalwareTypeID, Code, Name FROM dbo.MalwareType ORDER BY Name;", trace=False),
        "countries": db.query("SELECT CountryCode, Name FROM dbo.Country ORDER BY Name;", trace=False),
        "sectors": db.query("SELECT SectorID, Name FROM dbo.Sector ORDER BY Name;", trace=False),
        "tactics": db.query("SELECT TacticID, ExternalID, Name, ShortName FROM dbo.Tactic ORDER BY DisplayOrder;", trace=False),
        "riskBands": db.query("SELECT Code, Name, MinScore FROM dbo.RiskBand ORDER BY SortOrder;", trace=False),
    }


@router.get("/dashboard/attention")
def dashboard_attention(db: Db = Depends(get_db)):
    """Şu an bakılması gerekenler: tek satırda skaler alt sorgular (her biri indeksli bir sayım)."""
    return db.one(
        """
        DECLARE @now DATETIME2(0) = SYSUTCDATETIME();
        SELECT
            (SELECT COUNT(*) FROM dbo.Indicator AS i JOIN dbo.SeverityLevel AS s ON s.SeverityID = i.SeverityID
              WHERE i.Status = 'active' AND s.Code IN ('high', 'critical') AND i.LastSeen >= DATEADD(HOUR, -24, @now)) AS HighSeverity24h,
            (SELECT COUNT(DISTINCT IndicatorID) FROM dbo.Sighting WHERE SightedAt >= DATEADD(DAY, -7, @now))       AS Sighted7d,
            (SELECT COUNT(*) FROM dbo.Investigation WHERE Status <> 'closed')                                       AS OpenCases,
            (SELECT COUNT(*) FROM dbo.Investigation WHERE Status = 'investigating')                                 AS InvestigatingCases,
            (SELECT COUNT(*) FROM dbo.ImportJob WHERE StartedAt >= DATEADD(DAY, -7, @now) AND Status = 'failed')
              + (SELECT COUNT(*) FROM dbo.MaintenanceRun WHERE StartedAt >= DATEADD(DAY, -7, @now) AND Status = 'failed') AS FailedJobs7d,
            (SELECT COUNT(*) FROM dbo.DetectionCoverage)                                                            AS CoverageMarked,
            (SELECT COUNT(*) FROM dbo.fn_EffectiveCoverage() AS ec
              WHERE ec.Level = 0 AND (SELECT COUNT(*) FROM dbo.ActorTechnique AS x WHERE x.TechniqueID = ec.TechniqueID) >= 10) AS BlindSpots,
            (SELECT MAX(FinishedAt) FROM dbo.ImportJob WHERE Status = 'success' AND JobType = 'feed')             AS LastSyncAt;
        """)


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
              WHERE i.Status = 'active' AND s.Code IN ('high', 'critical'))              AS HighSeverityIOCs,
            (SELECT COUNT(*) FROM dbo.Indicator AS i JOIN dbo.SeverityLevel AS s ON s.SeverityID = i.SeverityID
              WHERE i.Status = 'active' AND s.Code IN ('high', 'critical')
                AND i.FirstSeen >= @start)                                               AS NewHighSeverityIOCs,
            (SELECT COUNT(*) FROM dbo.Campaign)                                          AS Campaigns,
            (SELECT COUNT(*) FROM dbo.Technique)                                         AS Techniques,
            (SELECT ISNULL(SUM(Quantity), 0) FROM dbo.Sighting WHERE SightedAt >= DATEADD(DAY, -7, @now)) AS Sightings7d,
            (SELECT CAST(MIN(StartedAt) AS DATE) FROM dbo.ImportJob WHERE JobType <> 'attack')   AS FirstImportDay;
        """, (days,))
    # Sayaçlar ve dağılımlar indexed view'dan (vw_IndicatorCounts, WITH NOEXPAND): satır taramadan, önceden toplanmış
    fast, by_severity, by_type = (db.query_sets("EXEC dbo.sp_IndicatorCountsFast;") + [[{}], [], []])[:3]
    kpi.update({k: v for k, v in (fast[0] if fast else {}).items() if v is not None and k != "HighRiskIOCs"})
    # Risk skoru bantları (RiskBand eşikleri). Sıfır olan bantlar da döner: grafik dağılımın tamamını gösterir.
    by_risk = db.query(
        """
        SELECT b.Code, b.Name, b.MinScore, b.SortOrder, COUNT(x.IndicatorID) AS Total
        FROM dbo.RiskBand AS b
        LEFT JOIN (SELECT v.IndicatorID, rb.Code
                   FROM dbo.vw_Indicator AS v CROSS APPLY dbo.fn_RiskBandOf(v.RiskScore) AS rb
                   WHERE v.Status = 'active') AS x ON x.Code = b.Code
        GROUP BY b.Code, b.Name, b.MinScore, b.SortOrder
        ORDER BY b.SortOrder;
        """)
    high_min = next((b["MinScore"] for b in by_risk if b["Code"] == "high"), 70)
    kpi["HighRiskIOCs"] = sum(b["Total"] for b in by_risk if b["MinScore"] >= high_min)   # yüksek + kritik bant
    kpi["HighRiskMin"] = high_min
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
               (SELECT TOP (1) CAST(m.IsPlaceholder AS BIT) FROM dbo.MalwareIndicator AS mi JOIN dbo.Malware AS m ON m.MalwareID = mi.MalwareID
                 WHERE mi.IndicatorID = v.IndicatorID ORDER BY m.IsPlaceholder) AS MalwarePlaceholder,
               (SELECT TOP (1) a.ViaName FROM dbo.vw_IndicatorAttribution AS a
                 WHERE a.IndicatorID = v.IndicatorID AND a.ViaType = 'campaign') AS CampaignName
        FROM dbo.vw_Indicator AS v
        ORDER BY v.LastSeen DESC, v.IndicatorID DESC;
        """)
    sources = db.query(
        """
        -- Birim: kaynak ne üretiyorsa o (IOC, zafiyet, teknik, IP aralığı, aile); "0 IOC" yanıltıcıydı
        -- Kapalı (devre dışı) kaynaklar da listelenir, en sonda
        SELECT h.SourceID, h.Name, h.Reliability, h.IsActive, h.IndicatorCount, h.EvidenceCount, h.LastJobID, h.LastRunAt, h.LastRunStatus,
               h.LastRowsInserted, h.LastRowsUpdated, h.LastRowsFailed, u.UnitLabel, u.UnitCount, u.UnitDetail
        FROM dbo.vw_SourceHealth AS h JOIN dbo.vw_SourceUnit AS u ON u.SourceID = h.SourceID
        ORDER BY h.IsActive DESC, CASE WHEN LastRunAt IS NULL THEN 1 ELSE 0 END, LastRunAt DESC, Name;
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
        -- yer tutucu aileler ("Unknown Loader") gerçek aile değildir: sıralamaya girmez
        SELECT TOP (6) m.MalwareID, m.Name, m.TypeName, m.IndicatorCount
        FROM dbo.vw_MalwareSummary AS m
        WHERE m.IndicatorCount > 0 AND m.IsPlaceholder = 0
        ORDER BY m.IndicatorCount DESC, m.Name;
        """)
    return {"kpi": kpi, "bySeverity": by_severity, "byRisk": by_risk, "byType": by_type, "trend": trend, "latest": latest,
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
