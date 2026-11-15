/* =====================================================================
   ThreatLens - 04: Görünümler (views)
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---------------------------------------------------------------------
   vw_Indicator: gösterge + sözlük adları + görülme sayısı + risk skoru.
   Uygulama gösterge listesini her zaman bu görünümden okur.
   --------------------------------------------------------------------- */
CREATE OR ALTER VIEW dbo.vw_Indicator
AS
SELECT
    i.IndicatorID,
    i.NormalizedValue AS Value,          -- arayüz her zaman kanonik biçimi gösterir
    i.Value AS OriginalValue,
    it.Code AS TypeCode, it.Name AS TypeName,
    i.Confidence,
    sv.SeverityID, sv.Code AS SeverityCode, sv.Name AS SeverityName,
    tl.Code AS TLPCode,
    s.SourceID, s.Name AS SourceName, s.Reliability,
    i.Description, i.FirstSeen, i.LastSeen, i.ExpiresAt, i.Status,
    CAST(CASE WHEN i.Status = 'active' THEN 1 ELSE 0 END AS BIT) AS IsActive,
    i.CreatedAt, i.UpdatedAt, CONVERT(VARCHAR(18), CAST(i.RowVer AS BINARY(8)), 1) AS RowVer,
    ISNULL(sc.SightingCount, 0) AS SightingCount,
    dbo.fn_RiskScore(i.Confidence, sv.Weight, i.LastSeen, sc.SightingCount, s.Reliability,
                     CASE WHEN i.Status = 'active' THEN 1 ELSE 0 END) AS RiskScore
FROM dbo.Indicator AS i
JOIN dbo.IndicatorType AS it ON it.TypeID = i.TypeID
JOIN dbo.SeverityLevel AS sv ON sv.SeverityID = i.SeverityID
JOIN dbo.TLPLevel      AS tl ON tl.TLPID = i.TLPID
JOIN dbo.Source        AS s  ON s.SourceID = i.SourceID
LEFT JOIN (
    SELECT IndicatorID, SUM(Quantity) AS SightingCount
    FROM dbo.Sighting
    GROUP BY IndicatorID
) AS sc ON sc.IndicatorID = i.IndicatorID;
GO

/* Aktör özeti: ilişkili kayıt sayıları (korelasyonlu alt sorgular) */
CREATE OR ALTER VIEW dbo.vw_ActorSummary
AS
SELECT
    a.ActorID, a.ExternalID, a.Name, a.Description, a.IsActive, a.FirstSeen, a.LastSeen,
    m.Name AS Motivation, a.CountryCode, c.Name AS CountryName,
    (SELECT COUNT(*) FROM dbo.ActorAlias     AS x WHERE x.ActorID = a.ActorID) AS AliasCount,
    (SELECT COUNT(*) FROM dbo.ActorMalware   AS x WHERE x.ActorID = a.ActorID) AS MalwareCount,
    (SELECT COUNT(*) FROM dbo.ActorTechnique AS x WHERE x.ActorID = a.ActorID) AS TechniqueCount,
    (SELECT COUNT(*) FROM dbo.Campaign       AS x WHERE x.ActorID = a.ActorID) AS CampaignCount
FROM dbo.ThreatActor AS a
LEFT JOIN dbo.Motivation AS m ON m.MotivationID = a.MotivationID
LEFT JOIN dbo.Country    AS c ON c.CountryCode = a.CountryCode;
GO

CREATE OR ALTER VIEW dbo.vw_MalwareSummary
AS
SELECT
    m.MalwareID, m.ExternalID, m.Name, m.Description, m.Platforms,
    mt.Code AS TypeCode, mt.Name AS TypeName,
    (SELECT COUNT(*) FROM dbo.ActorMalware     AS x WHERE x.MalwareID = m.MalwareID) AS ActorCount,
    (SELECT COUNT(*) FROM dbo.MalwareTechnique AS x WHERE x.MalwareID = m.MalwareID) AS TechniqueCount,
    (SELECT COUNT(*) FROM dbo.MalwareIndicator AS x WHERE x.MalwareID = m.MalwareID) AS IndicatorCount
FROM dbo.Malware AS m
JOIN dbo.MalwareType AS mt ON mt.MalwareTypeID = m.MalwareTypeID;
GO

CREATE OR ALTER VIEW dbo.vw_CampaignSummary
AS
SELECT
    c.CampaignID, c.ExternalID, c.Name, c.Description, c.StartDate, c.EndDate,
    c.ActorID, a.Name AS ActorName,
    CASE WHEN c.EndDate IS NULL THEN 1 ELSE 0 END AS IsOngoing,
    (SELECT COUNT(*) FROM dbo.CampaignMalware   AS x WHERE x.CampaignID = c.CampaignID) AS MalwareCount,
    (SELECT COUNT(*) FROM dbo.CampaignTechnique AS x WHERE x.CampaignID = c.CampaignID) AS TechniqueCount,
    (SELECT COUNT(*) FROM dbo.CampaignIndicator AS x WHERE x.CampaignID = c.CampaignID) AS IndicatorCount
FROM dbo.Campaign AS c
LEFT JOIN dbo.ThreatActor AS a ON a.ActorID = c.ActorID;
GO

/* ---------------------------------------------------------------------
   vw_GraphNode: graf düğümlerinin etiketleri (ad, kod) ilişkisel tablolardan gelir.
   Düğüm tabloları (03_graph.sql) yalnızca kimlik taşır; ad orada tekrar edilmez.
   Kenarlar ise 05_graph.sql'deki vw_GraphEdge görünümünde MATCH ile okunur.
   --------------------------------------------------------------------- */
CREATE OR ALTER VIEW dbo.vw_GraphNode
AS
SELECT 'actor' AS NodeType, CAST(ActorID AS BIGINT) AS NodeID, CAST(Name AS NVARCHAR(400)) AS Label, CAST(ExternalID AS NVARCHAR(50)) AS SubLabel FROM dbo.ThreatActor
UNION ALL
SELECT 'malware', CAST(MalwareID AS BIGINT), CAST(Name AS NVARCHAR(400)), CAST(ExternalID AS NVARCHAR(50)) FROM dbo.Malware
UNION ALL
SELECT 'campaign', CAST(CampaignID AS BIGINT), CAST(Name AS NVARCHAR(400)), CAST(ExternalID AS NVARCHAR(50)) FROM dbo.Campaign
UNION ALL
SELECT 'technique', CAST(TechniqueID AS BIGINT), CAST(Name AS NVARCHAR(400)), CAST(ExternalID AS NVARCHAR(50)) FROM dbo.Technique
UNION ALL
SELECT 'vulnerability', CAST(VulnerabilityID AS BIGINT), CAST(CveID AS NVARCHAR(400)), CAST(LEFT(Title, 50) AS NVARCHAR(50)) FROM dbo.Vulnerability
UNION ALL
SELECT 'indicator', i.IndicatorID, i.NormalizedValue, CAST(t.Code AS NVARCHAR(50))
FROM dbo.Indicator AS i JOIN dbo.IndicatorType AS t ON t.TypeID = i.TypeID;
GO

/* Kaynak sağlığı: her kaynağın gösterge sayısı, son içe aktarma işi ve son 7 gündeki başarı oranı */
CREATE OR ALTER VIEW dbo.vw_SourceHealth
AS
SELECT
    s.SourceID, s.Name, s.Url, s.Reliability, s.Description, s.IsActive,
    (SELECT COUNT(*) FROM dbo.Indicator AS i WHERE i.SourceID = s.SourceID) AS IndicatorCount,
    (SELECT COUNT(*) FROM dbo.Evidence  AS e WHERE e.SourceID = s.SourceID) AS EvidenceCount,
    lr.JobID AS LastJobID, lr.StartedAt AS LastRunAt, lr.Status AS LastRunStatus,
    lr.RowsInserted AS LastRowsInserted, lr.RowsUpdated AS LastRowsUpdated, lr.RowsFailed AS LastRowsFailed,
    w.Jobs7d, w.Failed7d
FROM dbo.Source AS s
OUTER APPLY (
    SELECT TOP (1) j.JobID, j.StartedAt, j.Status, j.RowsInserted, j.RowsUpdated, j.RowsFailed
    FROM dbo.ImportJob AS j
    WHERE j.SourceID = s.SourceID
    ORDER BY j.StartedAt DESC, j.JobID DESC
) AS lr
OUTER APPLY (
    SELECT COUNT(*) AS Jobs7d, SUM(CASE WHEN j.Status = 'failed' THEN 1 ELSE 0 END) AS Failed7d
    FROM dbo.ImportJob AS j
    WHERE j.SourceID = s.SourceID AND j.StartedAt >= DATEADD(DAY, -7, SYSUTCDATETIME())
) AS w;
GO
