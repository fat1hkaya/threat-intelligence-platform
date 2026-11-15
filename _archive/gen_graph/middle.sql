
/* vw_IndicatorAttribution: atıf zinciri.
     gösterge -(IndicatesMalware)-> zararlı <-(ActorUsesMalware)- aktör
     kampanya -(CampaignContainsIndicator)-> gösterge,  kampanya -(CampaignAttributedToActor)-> aktör
   Aktörü bilinmeyen zararlı/kampanya da listelenir (ActorID NULL). */
CREATE OR ALTER VIEW dbo.vw_IndicatorAttribution
AS
WITH via_malware AS (
    SELECT i.IndicatorID, m.MalwareID, e.Role, e.Confidence, e.EvidenceID
    FROM dbo.IndicatorNode AS i, dbo.IndicatesMalware AS e, dbo.MalwareNode AS m
    WHERE MATCH(i-(e)->m)
),
malware_actor AS (
    SELECT m.MalwareID, a.ActorID
    FROM dbo.ActorNode AS a, dbo.ActorUsesMalware AS e, dbo.MalwareNode AS m
    WHERE MATCH(a-(e)->m)
),
via_campaign AS (
    SELECT i.IndicatorID, c.CampaignID, e.Confidence, e.EvidenceID
    FROM dbo.CampaignNode AS c, dbo.CampaignContainsIndicator AS e, dbo.IndicatorNode AS i
    WHERE MATCH(c-(e)->i)
),
campaign_actor AS (
    SELECT c.CampaignID, a.ActorID
    FROM dbo.CampaignNode AS c, dbo.CampaignAttributedToActor AS e, dbo.ActorNode AS a
    WHERE MATCH(c-(e)->a)
)
SELECT v.IndicatorID, 'malware' AS ViaType, v.MalwareID AS ViaID, m.Name AS ViaName, v.Role, v.Confidence, v.EvidenceID,
       a.ActorID, a.Name AS ActorName
FROM via_malware AS v
JOIN dbo.Malware AS m ON m.MalwareID = v.MalwareID
LEFT JOIN malware_actor AS ma ON ma.MalwareID = v.MalwareID
LEFT JOIN dbo.ThreatActor AS a ON a.ActorID = ma.ActorID
UNION ALL
SELECT v.IndicatorID, 'campaign', v.CampaignID, c.Name, CAST(NULL AS VARCHAR(12)), v.Confidence, v.EvidenceID, a.ActorID, a.Name
FROM via_campaign AS v
JOIN dbo.Campaign AS c ON c.CampaignID = v.CampaignID
LEFT JOIN campaign_actor AS ca ON ca.CampaignID = v.CampaignID
LEFT JOIN dbo.ThreatActor AS a ON a.ActorID = ca.ActorID;
GO

/* ---------- 4. Eşitleme: ilişkisel model -> graf ---------- */
CREATE OR ALTER PROCEDURE dbo.sp_SyncGraph
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    BEGIN TRY
        BEGIN TRANSACTION;

        /* 4.1 Düğümler: ilişkisel kaydı silinmiş düğümü kaldır (kenarları kısıtla birlikte silinir), eksik düğümü ekle */
