/* =====================================================================
   ThreatLens - 05: SQL Server Graph katmanı (AS NODE / AS EDGE)
   ---------------------------------------------------------------------
   İlişkisel tablolar verinin asıl kaynağıdır (schema/01_tables.sql). Bu dosya aynı
   ilişkileri SQL Graph düğüm ve kenar tablolarına taşır; böylece çok adımlı
   sorular (gösterge -> zararlı -> aktör) MATCH ile, "iki aktör arasında kaç
   adım var" sorusu SHORTEST_PATH ile sorulabilir.

   Tasarım kararları
   - Düğüm tablosu yalnızca ilişkisel kaydın anahtarını taşır (UNIQUE). Ad,
     açıklama gibi nitelikler tekrar edilmez; vw_GraphNode ile birleştirilir.
   - Her kenar tablosunda kenar kısıtı (CONNECTION) vardır: yön ve uç tipleri
     veritabanında sabittir, yanlış tipte iki düğüm bağlanamaz.
   - ON DELETE CASCADE: düğüm silinince kenarları da silinir (sarkık kenar kalmaz).
   - Tutarlılık: her ilişkisel tabloda tetikleyici vardır. Kayıt veya ilişki eklenip
     silindiğinde düğüm/kenar AYNI transaction içinde güncellenir; işlem geri alınırsa
     graf değişikliği de geri alınır. sp_SyncGraph tüm grafı ilişkisel modelden yeniden
     kurar (ilk yükleme, onarım); sp_CheckGraphConsistency iki modeli karşılaştırır.
   Gereksinim: SQL Server 2019 veya üzeri (kenar kısıtı ve SHORTEST_PATH).
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---------- 1. Düğüm tabloları ----------
   Her düğüm, ilişkisel kaydının anahtarını benzersiz olarak taşır (1:1 eşleme). */
CREATE TABLE dbo.IndicatorNode (
    IndicatorID BIGINT NOT NULL CONSTRAINT UQ_IndicatorNode_IndicatorID UNIQUE
) AS NODE;
CREATE TABLE dbo.MalwareNode (
    MalwareID INT NOT NULL CONSTRAINT UQ_MalwareNode_MalwareID UNIQUE
) AS NODE;
CREATE TABLE dbo.ActorNode (
    ActorID INT NOT NULL CONSTRAINT UQ_ActorNode_ActorID UNIQUE
) AS NODE;
CREATE TABLE dbo.CampaignNode (
    CampaignID INT NOT NULL CONSTRAINT UQ_CampaignNode_CampaignID UNIQUE
) AS NODE;
CREATE TABLE dbo.TechniqueNode (
    TechniqueID INT NOT NULL CONSTRAINT UQ_TechniqueNode_TechniqueID UNIQUE
) AS NODE;
CREATE TABLE dbo.VulnerabilityNode (
    VulnerabilityID INT NOT NULL CONSTRAINT UQ_VulnerabilityNode_VulnerabilityID UNIQUE
) AS NODE;
GO

/* ---------- 2. Kenar tabloları ----------
   Yön: gösterge -> zararlı, aktör -> zararlı/teknik, zararlı -> teknik/zafiyet, kampanya -> aktör/zararlı/teknik/gösterge.
   Confidence ve EvidenceID, ilişkisel ara tablodaki değerlerin yansımasıdır (ilişki detay panelinde gösterilir).
   Kenar kısıtı (CONNECTION): yanlış tipte iki düğüm bağlanamaz; düğüm silinince kenarı da silinir. */
CREATE TABLE dbo.IndicatesMalware (
    Role       VARCHAR(12)  NOT NULL CONSTRAINT DF_IndicatesMalware_Role DEFAULT ('other'),
    Confidence TINYINT NULL,
    EvidenceID INT NULL,
    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_IndicatesMalware_CreatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT EC_IndicatesMalware CONNECTION (dbo.IndicatorNode TO dbo.MalwareNode) ON DELETE CASCADE
) AS EDGE;
CREATE TABLE dbo.ActorUsesMalware (
    Confidence TINYINT NULL,
    EvidenceID INT NULL,
    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_ActorUsesMalware_CreatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT EC_ActorUsesMalware CONNECTION (dbo.ActorNode TO dbo.MalwareNode) ON DELETE CASCADE
) AS EDGE;
CREATE TABLE dbo.ActorUsesTechnique (
    Confidence TINYINT NULL,
    EvidenceID INT NULL,
    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_ActorUsesTechnique_CreatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT EC_ActorUsesTechnique CONNECTION (dbo.ActorNode TO dbo.TechniqueNode) ON DELETE CASCADE
) AS EDGE;
CREATE TABLE dbo.MalwareUsesTechnique (
    Confidence TINYINT NULL,
    EvidenceID INT NULL,
    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_MalwareUsesTechnique_CreatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT EC_MalwareUsesTechnique CONNECTION (dbo.MalwareNode TO dbo.TechniqueNode) ON DELETE CASCADE
) AS EDGE;
CREATE TABLE dbo.MalwareExploitsVulnerability (
    Confidence TINYINT NULL,
    EvidenceID INT NULL,
    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_MalwareExploitsVulnerability_CreatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT EC_MalwareExploitsVulnerability CONNECTION (dbo.MalwareNode TO dbo.VulnerabilityNode) ON DELETE CASCADE
) AS EDGE;
CREATE TABLE dbo.CampaignAttributedToActor (
    Confidence TINYINT NULL,
    EvidenceID INT NULL,
    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_CampaignAttributedToActor_CreatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT EC_CampaignAttributedToActor CONNECTION (dbo.CampaignNode TO dbo.ActorNode) ON DELETE CASCADE
) AS EDGE;
CREATE TABLE dbo.CampaignUsesMalware (
    Confidence TINYINT NULL,
    EvidenceID INT NULL,
    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_CampaignUsesMalware_CreatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT EC_CampaignUsesMalware CONNECTION (dbo.CampaignNode TO dbo.MalwareNode) ON DELETE CASCADE
) AS EDGE;
CREATE TABLE dbo.CampaignUsesTechnique (
    Confidence TINYINT NULL,
    EvidenceID INT NULL,
    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_CampaignUsesTechnique_CreatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT EC_CampaignUsesTechnique CONNECTION (dbo.CampaignNode TO dbo.TechniqueNode) ON DELETE CASCADE
) AS EDGE;
CREATE TABLE dbo.CampaignContainsIndicator (
    Confidence TINYINT NULL,
    EvidenceID INT NULL,
    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_CampaignContainsIndicator_CreatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT EC_CampaignContainsIndicator CONNECTION (dbo.CampaignNode TO dbo.IndicatorNode) ON DELETE CASCADE
) AS EDGE;

/* Türetilmiş kenar: en az 3 ortak zararlı yazılım/araç kullanan iki aktör (iki yönde).
   SHORTEST_PATH için tek tip düğüm ve kenar gerekir; aktörler arası yol bu kenar üzerinden aranır. */
CREATE TABLE dbo.ActorSharesToolsWith (
    SharedCount INT NOT NULL,
    CONSTRAINT CK_ActorSharesToolsWith_SharedCount CHECK (SharedCount >= 3),
    CONSTRAINT EC_ActorSharesToolsWith CONNECTION (dbo.ActorNode TO dbo.ActorNode) ON DELETE CASCADE
) AS EDGE;
GO

/* $from_id / $to_id için varsayılan indeks yoktur; iki yönde gezinme için eklenir */
CREATE UNIQUE NONCLUSTERED INDEX UX_IndicatesMalware_FromTo ON dbo.IndicatesMalware ($from_id, $to_id);
CREATE NONCLUSTERED INDEX IX_IndicatesMalware_To ON dbo.IndicatesMalware ($to_id);
CREATE UNIQUE NONCLUSTERED INDEX UX_ActorUsesMalware_FromTo ON dbo.ActorUsesMalware ($from_id, $to_id);
CREATE NONCLUSTERED INDEX IX_ActorUsesMalware_To ON dbo.ActorUsesMalware ($to_id);
CREATE UNIQUE NONCLUSTERED INDEX UX_ActorUsesTechnique_FromTo ON dbo.ActorUsesTechnique ($from_id, $to_id);
CREATE NONCLUSTERED INDEX IX_ActorUsesTechnique_To ON dbo.ActorUsesTechnique ($to_id);
CREATE UNIQUE NONCLUSTERED INDEX UX_MalwareUsesTechnique_FromTo ON dbo.MalwareUsesTechnique ($from_id, $to_id);
CREATE NONCLUSTERED INDEX IX_MalwareUsesTechnique_To ON dbo.MalwareUsesTechnique ($to_id);
CREATE UNIQUE NONCLUSTERED INDEX UX_MalwareExploitsVulnerability_FromTo ON dbo.MalwareExploitsVulnerability ($from_id, $to_id);
CREATE NONCLUSTERED INDEX IX_MalwareExploitsVulnerability_To ON dbo.MalwareExploitsVulnerability ($to_id);
CREATE UNIQUE NONCLUSTERED INDEX UX_CampaignAttributedToActor_FromTo ON dbo.CampaignAttributedToActor ($from_id, $to_id);
CREATE NONCLUSTERED INDEX IX_CampaignAttributedToActor_To ON dbo.CampaignAttributedToActor ($to_id);
CREATE UNIQUE NONCLUSTERED INDEX UX_CampaignUsesMalware_FromTo ON dbo.CampaignUsesMalware ($from_id, $to_id);
CREATE NONCLUSTERED INDEX IX_CampaignUsesMalware_To ON dbo.CampaignUsesMalware ($to_id);
CREATE UNIQUE NONCLUSTERED INDEX UX_CampaignUsesTechnique_FromTo ON dbo.CampaignUsesTechnique ($from_id, $to_id);
CREATE NONCLUSTERED INDEX IX_CampaignUsesTechnique_To ON dbo.CampaignUsesTechnique ($to_id);
CREATE UNIQUE NONCLUSTERED INDEX UX_CampaignContainsIndicator_FromTo ON dbo.CampaignContainsIndicator ($from_id, $to_id);
CREATE NONCLUSTERED INDEX IX_CampaignContainsIndicator_To ON dbo.CampaignContainsIndicator ($to_id);
CREATE UNIQUE NONCLUSTERED INDEX UX_ActorSharesToolsWith_FromTo ON dbo.ActorSharesToolsWith ($from_id, $to_id);
CREATE NONCLUSTERED INDEX IX_ActorSharesToolsWith_To ON dbo.ActorSharesToolsWith ($to_id);
GO

/* ---------- 3. MATCH tabanlı görünümler ---------- */

/* vw_GraphEdge: tüm kenar tipleri MATCH ile okunup tek biçimde birleştirilir.
   İlişki grafı ekranı (sp_GetNeighborhood) kenarları buradan okur. */
CREATE OR ALTER VIEW dbo.vw_GraphEdge
AS
SELECT 'indicator' AS SourceType, CAST(a.IndicatorID AS BIGINT) AS SourceID, 'malware' AS TargetType, CAST(b.MalwareID AS BIGINT) AS TargetID,
       'indicates' AS Relation, e.Confidence, e.EvidenceID
FROM dbo.IndicatorNode AS a, dbo.IndicatesMalware AS e, dbo.MalwareNode AS b
WHERE MATCH(a-(e)->b)
UNION ALL
SELECT 'actor' AS SourceType, CAST(a.ActorID AS BIGINT) AS SourceID, 'malware' AS TargetType, CAST(b.MalwareID AS BIGINT) AS TargetID,
       'uses' AS Relation, e.Confidence, e.EvidenceID
FROM dbo.ActorNode AS a, dbo.ActorUsesMalware AS e, dbo.MalwareNode AS b
WHERE MATCH(a-(e)->b)
UNION ALL
SELECT 'actor' AS SourceType, CAST(a.ActorID AS BIGINT) AS SourceID, 'technique' AS TargetType, CAST(b.TechniqueID AS BIGINT) AS TargetID,
       'uses' AS Relation, e.Confidence, e.EvidenceID
FROM dbo.ActorNode AS a, dbo.ActorUsesTechnique AS e, dbo.TechniqueNode AS b
WHERE MATCH(a-(e)->b)
UNION ALL
SELECT 'malware' AS SourceType, CAST(a.MalwareID AS BIGINT) AS SourceID, 'technique' AS TargetType, CAST(b.TechniqueID AS BIGINT) AS TargetID,
       'uses' AS Relation, e.Confidence, e.EvidenceID
FROM dbo.MalwareNode AS a, dbo.MalwareUsesTechnique AS e, dbo.TechniqueNode AS b
WHERE MATCH(a-(e)->b)
UNION ALL
SELECT 'malware' AS SourceType, CAST(a.MalwareID AS BIGINT) AS SourceID, 'vulnerability' AS TargetType, CAST(b.VulnerabilityID AS BIGINT) AS TargetID,
       'exploits' AS Relation, e.Confidence, e.EvidenceID
FROM dbo.MalwareNode AS a, dbo.MalwareExploitsVulnerability AS e, dbo.VulnerabilityNode AS b
WHERE MATCH(a-(e)->b)
UNION ALL
SELECT 'campaign' AS SourceType, CAST(a.CampaignID AS BIGINT) AS SourceID, 'actor' AS TargetType, CAST(b.ActorID AS BIGINT) AS TargetID,
       'attributed-to' AS Relation, e.Confidence, e.EvidenceID
FROM dbo.CampaignNode AS a, dbo.CampaignAttributedToActor AS e, dbo.ActorNode AS b
WHERE MATCH(a-(e)->b)
UNION ALL
SELECT 'campaign' AS SourceType, CAST(a.CampaignID AS BIGINT) AS SourceID, 'malware' AS TargetType, CAST(b.MalwareID AS BIGINT) AS TargetID,
       'uses' AS Relation, e.Confidence, e.EvidenceID
FROM dbo.CampaignNode AS a, dbo.CampaignUsesMalware AS e, dbo.MalwareNode AS b
WHERE MATCH(a-(e)->b)
UNION ALL
SELECT 'campaign' AS SourceType, CAST(a.CampaignID AS BIGINT) AS SourceID, 'technique' AS TargetType, CAST(b.TechniqueID AS BIGINT) AS TargetID,
       'uses' AS Relation, e.Confidence, e.EvidenceID
FROM dbo.CampaignNode AS a, dbo.CampaignUsesTechnique AS e, dbo.TechniqueNode AS b
WHERE MATCH(a-(e)->b)
UNION ALL
SELECT 'campaign' AS SourceType, CAST(a.CampaignID AS BIGINT) AS SourceID, 'indicator' AS TargetType, CAST(b.IndicatorID AS BIGINT) AS TargetID,
       'observed' AS Relation, e.Confidence, e.EvidenceID
FROM dbo.CampaignNode AS a, dbo.CampaignContainsIndicator AS e, dbo.IndicatorNode AS b
WHERE MATCH(a-(e)->b);
GO

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
SELECT v.IndicatorID, 'malware' AS ViaType, v.MalwareID AS ViaID, dbo.fn_MalwareLabel(m.Name, m.ExternalID) AS ViaName, v.Role, v.Confidence, v.EvidenceID,
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
        DELETE n FROM dbo.IndicatorNode AS n WHERE NOT EXISTS (SELECT 1 FROM dbo.Indicator AS r WHERE r.IndicatorID = n.IndicatorID);
        INSERT INTO dbo.IndicatorNode (IndicatorID)
        SELECT r.IndicatorID FROM dbo.Indicator AS r WHERE NOT EXISTS (SELECT 1 FROM dbo.IndicatorNode AS n WHERE n.IndicatorID = r.IndicatorID);

        DELETE n FROM dbo.MalwareNode AS n WHERE NOT EXISTS (SELECT 1 FROM dbo.Malware AS r WHERE r.MalwareID = n.MalwareID);
        INSERT INTO dbo.MalwareNode (MalwareID)
        SELECT r.MalwareID FROM dbo.Malware AS r WHERE NOT EXISTS (SELECT 1 FROM dbo.MalwareNode AS n WHERE n.MalwareID = r.MalwareID);

        DELETE n FROM dbo.ActorNode AS n WHERE NOT EXISTS (SELECT 1 FROM dbo.ThreatActor AS r WHERE r.ActorID = n.ActorID);
        INSERT INTO dbo.ActorNode (ActorID)
        SELECT r.ActorID FROM dbo.ThreatActor AS r WHERE NOT EXISTS (SELECT 1 FROM dbo.ActorNode AS n WHERE n.ActorID = r.ActorID);

        DELETE n FROM dbo.CampaignNode AS n WHERE NOT EXISTS (SELECT 1 FROM dbo.Campaign AS r WHERE r.CampaignID = n.CampaignID);
        INSERT INTO dbo.CampaignNode (CampaignID)
        SELECT r.CampaignID FROM dbo.Campaign AS r WHERE NOT EXISTS (SELECT 1 FROM dbo.CampaignNode AS n WHERE n.CampaignID = r.CampaignID);

        DELETE n FROM dbo.TechniqueNode AS n WHERE NOT EXISTS (SELECT 1 FROM dbo.Technique AS r WHERE r.TechniqueID = n.TechniqueID);
        INSERT INTO dbo.TechniqueNode (TechniqueID)
        SELECT r.TechniqueID FROM dbo.Technique AS r WHERE NOT EXISTS (SELECT 1 FROM dbo.TechniqueNode AS n WHERE n.TechniqueID = r.TechniqueID);

        DELETE n FROM dbo.VulnerabilityNode AS n WHERE NOT EXISTS (SELECT 1 FROM dbo.Vulnerability AS r WHERE r.VulnerabilityID = n.VulnerabilityID);
        INSERT INTO dbo.VulnerabilityNode (VulnerabilityID)
        SELECT r.VulnerabilityID FROM dbo.Vulnerability AS r WHERE NOT EXISTS (SELECT 1 FROM dbo.VulnerabilityNode AS n WHERE n.VulnerabilityID = r.VulnerabilityID);

        /* 4.2 Kenarlar. MATCH yalnızca SELECT içinde kullanılabildiği için önce mevcut kenarlar
           MATCH ile #cur tablosuna okunur, ardından değişiklikler $edge_id üzerinden yapılır. */
        CREATE TABLE #cur (EdgeID NVARCHAR(1000) COLLATE DATABASE_DEFAULT NOT NULL, FromKey BIGINT NOT NULL, ToKey BIGINT NOT NULL,
                           Role VARCHAR(12) COLLATE DATABASE_DEFAULT NULL, Confidence TINYINT NULL, EvidenceID INT NULL);

        -- IndicatesMalware: indicator -> malware
        TRUNCATE TABLE #cur;
        INSERT INTO #cur (EdgeID, FromKey, ToKey, Role, Confidence, EvidenceID)
        SELECT e.$edge_id, a.IndicatorID, b.MalwareID, e.Role, e.Confidence, e.EvidenceID
        FROM dbo.IndicatorNode AS a, dbo.IndicatesMalware AS e, dbo.MalwareNode AS b
        WHERE MATCH(a-(e)->b);

        DELETE FROM dbo.IndicatesMalware
        WHERE $edge_id IN (SELECT c.EdgeID FROM #cur AS c
                           WHERE NOT EXISTS (SELECT 1 FROM dbo.MalwareIndicator AS x WHERE x.IndicatorID = c.FromKey AND x.MalwareID = c.ToKey));

        INSERT INTO dbo.IndicatesMalware ($from_id, $to_id, Role, Confidence, EvidenceID)
        SELECT a.$node_id, b.$node_id, x.Role, x.Confidence, x.EvidenceID
        FROM dbo.MalwareIndicator AS x
        JOIN dbo.IndicatorNode AS a ON a.IndicatorID = x.IndicatorID
        JOIN dbo.MalwareNode AS b ON b.MalwareID = x.MalwareID
        WHERE NOT EXISTS (SELECT 1 FROM #cur AS c WHERE c.FromKey = x.IndicatorID AND c.ToKey = x.MalwareID);

        UPDATE e SET Role = x.Role, Confidence = x.Confidence, EvidenceID = x.EvidenceID
        FROM dbo.IndicatesMalware AS e
        JOIN #cur AS c ON c.EdgeID = e.$edge_id
        JOIN dbo.MalwareIndicator AS x ON x.IndicatorID = c.FromKey AND x.MalwareID = c.ToKey
        WHERE EXISTS (SELECT c.Role, c.Confidence, c.EvidenceID EXCEPT SELECT x.Role, x.Confidence, x.EvidenceID);

        -- ActorUsesMalware: actor -> malware
        TRUNCATE TABLE #cur;
        INSERT INTO #cur (EdgeID, FromKey, ToKey, Role, Confidence, EvidenceID)
        SELECT e.$edge_id, a.ActorID, b.MalwareID, NULL, e.Confidence, e.EvidenceID
        FROM dbo.ActorNode AS a, dbo.ActorUsesMalware AS e, dbo.MalwareNode AS b
        WHERE MATCH(a-(e)->b);

        DELETE FROM dbo.ActorUsesMalware
        WHERE $edge_id IN (SELECT c.EdgeID FROM #cur AS c
                           WHERE NOT EXISTS (SELECT 1 FROM dbo.ActorMalware AS x WHERE x.ActorID = c.FromKey AND x.MalwareID = c.ToKey));

        INSERT INTO dbo.ActorUsesMalware ($from_id, $to_id, Confidence, EvidenceID)
        SELECT a.$node_id, b.$node_id, x.Confidence, x.EvidenceID
        FROM dbo.ActorMalware AS x
        JOIN dbo.ActorNode AS a ON a.ActorID = x.ActorID
        JOIN dbo.MalwareNode AS b ON b.MalwareID = x.MalwareID
        WHERE NOT EXISTS (SELECT 1 FROM #cur AS c WHERE c.FromKey = x.ActorID AND c.ToKey = x.MalwareID);

        UPDATE e SET Confidence = x.Confidence, EvidenceID = x.EvidenceID
        FROM dbo.ActorUsesMalware AS e
        JOIN #cur AS c ON c.EdgeID = e.$edge_id
        JOIN dbo.ActorMalware AS x ON x.ActorID = c.FromKey AND x.MalwareID = c.ToKey
        WHERE EXISTS (SELECT c.Role, c.Confidence, c.EvidenceID EXCEPT SELECT NULL, x.Confidence, x.EvidenceID);

        -- ActorUsesTechnique: actor -> technique
        TRUNCATE TABLE #cur;
        INSERT INTO #cur (EdgeID, FromKey, ToKey, Role, Confidence, EvidenceID)
        SELECT e.$edge_id, a.ActorID, b.TechniqueID, NULL, e.Confidence, e.EvidenceID
        FROM dbo.ActorNode AS a, dbo.ActorUsesTechnique AS e, dbo.TechniqueNode AS b
        WHERE MATCH(a-(e)->b);

        DELETE FROM dbo.ActorUsesTechnique
        WHERE $edge_id IN (SELECT c.EdgeID FROM #cur AS c
                           WHERE NOT EXISTS (SELECT 1 FROM dbo.ActorTechnique AS x WHERE x.ActorID = c.FromKey AND x.TechniqueID = c.ToKey));

        INSERT INTO dbo.ActorUsesTechnique ($from_id, $to_id, Confidence, EvidenceID)
        SELECT a.$node_id, b.$node_id, x.Confidence, x.EvidenceID
        FROM dbo.ActorTechnique AS x
        JOIN dbo.ActorNode AS a ON a.ActorID = x.ActorID
        JOIN dbo.TechniqueNode AS b ON b.TechniqueID = x.TechniqueID
        WHERE NOT EXISTS (SELECT 1 FROM #cur AS c WHERE c.FromKey = x.ActorID AND c.ToKey = x.TechniqueID);

        UPDATE e SET Confidence = x.Confidence, EvidenceID = x.EvidenceID
        FROM dbo.ActorUsesTechnique AS e
        JOIN #cur AS c ON c.EdgeID = e.$edge_id
        JOIN dbo.ActorTechnique AS x ON x.ActorID = c.FromKey AND x.TechniqueID = c.ToKey
        WHERE EXISTS (SELECT c.Role, c.Confidence, c.EvidenceID EXCEPT SELECT NULL, x.Confidence, x.EvidenceID);

        -- MalwareUsesTechnique: malware -> technique
        TRUNCATE TABLE #cur;
        INSERT INTO #cur (EdgeID, FromKey, ToKey, Role, Confidence, EvidenceID)
        SELECT e.$edge_id, a.MalwareID, b.TechniqueID, NULL, e.Confidence, e.EvidenceID
        FROM dbo.MalwareNode AS a, dbo.MalwareUsesTechnique AS e, dbo.TechniqueNode AS b
        WHERE MATCH(a-(e)->b);

        DELETE FROM dbo.MalwareUsesTechnique
        WHERE $edge_id IN (SELECT c.EdgeID FROM #cur AS c
                           WHERE NOT EXISTS (SELECT 1 FROM dbo.MalwareTechnique AS x WHERE x.MalwareID = c.FromKey AND x.TechniqueID = c.ToKey));

        INSERT INTO dbo.MalwareUsesTechnique ($from_id, $to_id, Confidence, EvidenceID)
        SELECT a.$node_id, b.$node_id, x.Confidence, x.EvidenceID
        FROM dbo.MalwareTechnique AS x
        JOIN dbo.MalwareNode AS a ON a.MalwareID = x.MalwareID
        JOIN dbo.TechniqueNode AS b ON b.TechniqueID = x.TechniqueID
        WHERE NOT EXISTS (SELECT 1 FROM #cur AS c WHERE c.FromKey = x.MalwareID AND c.ToKey = x.TechniqueID);

        UPDATE e SET Confidence = x.Confidence, EvidenceID = x.EvidenceID
        FROM dbo.MalwareUsesTechnique AS e
        JOIN #cur AS c ON c.EdgeID = e.$edge_id
        JOIN dbo.MalwareTechnique AS x ON x.MalwareID = c.FromKey AND x.TechniqueID = c.ToKey
        WHERE EXISTS (SELECT c.Role, c.Confidence, c.EvidenceID EXCEPT SELECT NULL, x.Confidence, x.EvidenceID);

        -- MalwareExploitsVulnerability: malware -> vulnerability
        TRUNCATE TABLE #cur;
        INSERT INTO #cur (EdgeID, FromKey, ToKey, Role, Confidence, EvidenceID)
        SELECT e.$edge_id, a.MalwareID, b.VulnerabilityID, NULL, e.Confidence, e.EvidenceID
        FROM dbo.MalwareNode AS a, dbo.MalwareExploitsVulnerability AS e, dbo.VulnerabilityNode AS b
        WHERE MATCH(a-(e)->b);

        DELETE FROM dbo.MalwareExploitsVulnerability
        WHERE $edge_id IN (SELECT c.EdgeID FROM #cur AS c
                           WHERE NOT EXISTS (SELECT 1 FROM dbo.MalwareVulnerability AS x WHERE x.MalwareID = c.FromKey AND x.VulnerabilityID = c.ToKey));

        INSERT INTO dbo.MalwareExploitsVulnerability ($from_id, $to_id, Confidence, EvidenceID)
        SELECT a.$node_id, b.$node_id, x.Confidence, x.EvidenceID
        FROM dbo.MalwareVulnerability AS x
        JOIN dbo.MalwareNode AS a ON a.MalwareID = x.MalwareID
        JOIN dbo.VulnerabilityNode AS b ON b.VulnerabilityID = x.VulnerabilityID
        WHERE NOT EXISTS (SELECT 1 FROM #cur AS c WHERE c.FromKey = x.MalwareID AND c.ToKey = x.VulnerabilityID);

        UPDATE e SET Confidence = x.Confidence, EvidenceID = x.EvidenceID
        FROM dbo.MalwareExploitsVulnerability AS e
        JOIN #cur AS c ON c.EdgeID = e.$edge_id
        JOIN dbo.MalwareVulnerability AS x ON x.MalwareID = c.FromKey AND x.VulnerabilityID = c.ToKey
        WHERE EXISTS (SELECT c.Role, c.Confidence, c.EvidenceID EXCEPT SELECT NULL, x.Confidence, x.EvidenceID);

        -- CampaignAttributedToActor: campaign -> actor
        TRUNCATE TABLE #cur;
        INSERT INTO #cur (EdgeID, FromKey, ToKey, Role, Confidence, EvidenceID)
        SELECT e.$edge_id, a.CampaignID, b.ActorID, NULL, e.Confidence, e.EvidenceID
        FROM dbo.CampaignNode AS a, dbo.CampaignAttributedToActor AS e, dbo.ActorNode AS b
        WHERE MATCH(a-(e)->b);

        DELETE FROM dbo.CampaignAttributedToActor
        WHERE $edge_id IN (SELECT c.EdgeID FROM #cur AS c
                           WHERE NOT EXISTS (SELECT 1 FROM dbo.Campaign AS x WHERE x.CampaignID = c.FromKey AND x.ActorID = c.ToKey AND x.ActorID IS NOT NULL));

        INSERT INTO dbo.CampaignAttributedToActor ($from_id, $to_id, Confidence, EvidenceID)
        SELECT a.$node_id, b.$node_id, CAST(NULL AS TINYINT), x.AttributionEvidenceID
        FROM dbo.Campaign AS x
        JOIN dbo.CampaignNode AS a ON a.CampaignID = x.CampaignID
        JOIN dbo.ActorNode AS b ON b.ActorID = x.ActorID
        WHERE NOT EXISTS (SELECT 1 FROM #cur AS c WHERE c.FromKey = x.CampaignID AND c.ToKey = x.ActorID);

        UPDATE e SET Confidence = CAST(NULL AS TINYINT), EvidenceID = x.AttributionEvidenceID
        FROM dbo.CampaignAttributedToActor AS e
        JOIN #cur AS c ON c.EdgeID = e.$edge_id
        JOIN dbo.Campaign AS x ON x.CampaignID = c.FromKey AND x.ActorID = c.ToKey
        WHERE EXISTS (SELECT c.Role, c.Confidence, c.EvidenceID EXCEPT SELECT NULL, CAST(NULL AS TINYINT), x.AttributionEvidenceID);

        -- CampaignUsesMalware: campaign -> malware
        TRUNCATE TABLE #cur;
        INSERT INTO #cur (EdgeID, FromKey, ToKey, Role, Confidence, EvidenceID)
        SELECT e.$edge_id, a.CampaignID, b.MalwareID, NULL, e.Confidence, e.EvidenceID
        FROM dbo.CampaignNode AS a, dbo.CampaignUsesMalware AS e, dbo.MalwareNode AS b
        WHERE MATCH(a-(e)->b);

        DELETE FROM dbo.CampaignUsesMalware
        WHERE $edge_id IN (SELECT c.EdgeID FROM #cur AS c
                           WHERE NOT EXISTS (SELECT 1 FROM dbo.CampaignMalware AS x WHERE x.CampaignID = c.FromKey AND x.MalwareID = c.ToKey));

        INSERT INTO dbo.CampaignUsesMalware ($from_id, $to_id, Confidence, EvidenceID)
        SELECT a.$node_id, b.$node_id, x.Confidence, x.EvidenceID
        FROM dbo.CampaignMalware AS x
        JOIN dbo.CampaignNode AS a ON a.CampaignID = x.CampaignID
        JOIN dbo.MalwareNode AS b ON b.MalwareID = x.MalwareID
        WHERE NOT EXISTS (SELECT 1 FROM #cur AS c WHERE c.FromKey = x.CampaignID AND c.ToKey = x.MalwareID);

        UPDATE e SET Confidence = x.Confidence, EvidenceID = x.EvidenceID
        FROM dbo.CampaignUsesMalware AS e
        JOIN #cur AS c ON c.EdgeID = e.$edge_id
        JOIN dbo.CampaignMalware AS x ON x.CampaignID = c.FromKey AND x.MalwareID = c.ToKey
        WHERE EXISTS (SELECT c.Role, c.Confidence, c.EvidenceID EXCEPT SELECT NULL, x.Confidence, x.EvidenceID);

        -- CampaignUsesTechnique: campaign -> technique
        TRUNCATE TABLE #cur;
        INSERT INTO #cur (EdgeID, FromKey, ToKey, Role, Confidence, EvidenceID)
        SELECT e.$edge_id, a.CampaignID, b.TechniqueID, NULL, e.Confidence, e.EvidenceID
        FROM dbo.CampaignNode AS a, dbo.CampaignUsesTechnique AS e, dbo.TechniqueNode AS b
        WHERE MATCH(a-(e)->b);

        DELETE FROM dbo.CampaignUsesTechnique
        WHERE $edge_id IN (SELECT c.EdgeID FROM #cur AS c
                           WHERE NOT EXISTS (SELECT 1 FROM dbo.CampaignTechnique AS x WHERE x.CampaignID = c.FromKey AND x.TechniqueID = c.ToKey));

        INSERT INTO dbo.CampaignUsesTechnique ($from_id, $to_id, Confidence, EvidenceID)
        SELECT a.$node_id, b.$node_id, x.Confidence, x.EvidenceID
        FROM dbo.CampaignTechnique AS x
        JOIN dbo.CampaignNode AS a ON a.CampaignID = x.CampaignID
        JOIN dbo.TechniqueNode AS b ON b.TechniqueID = x.TechniqueID
        WHERE NOT EXISTS (SELECT 1 FROM #cur AS c WHERE c.FromKey = x.CampaignID AND c.ToKey = x.TechniqueID);

        UPDATE e SET Confidence = x.Confidence, EvidenceID = x.EvidenceID
        FROM dbo.CampaignUsesTechnique AS e
        JOIN #cur AS c ON c.EdgeID = e.$edge_id
        JOIN dbo.CampaignTechnique AS x ON x.CampaignID = c.FromKey AND x.TechniqueID = c.ToKey
        WHERE EXISTS (SELECT c.Role, c.Confidence, c.EvidenceID EXCEPT SELECT NULL, x.Confidence, x.EvidenceID);

        -- CampaignContainsIndicator: campaign -> indicator
        TRUNCATE TABLE #cur;
        INSERT INTO #cur (EdgeID, FromKey, ToKey, Role, Confidence, EvidenceID)
        SELECT e.$edge_id, a.CampaignID, b.IndicatorID, NULL, e.Confidence, e.EvidenceID
        FROM dbo.CampaignNode AS a, dbo.CampaignContainsIndicator AS e, dbo.IndicatorNode AS b
        WHERE MATCH(a-(e)->b);

        DELETE FROM dbo.CampaignContainsIndicator
        WHERE $edge_id IN (SELECT c.EdgeID FROM #cur AS c
                           WHERE NOT EXISTS (SELECT 1 FROM dbo.CampaignIndicator AS x WHERE x.CampaignID = c.FromKey AND x.IndicatorID = c.ToKey));

        INSERT INTO dbo.CampaignContainsIndicator ($from_id, $to_id, Confidence, EvidenceID)
        SELECT a.$node_id, b.$node_id, x.Confidence, x.EvidenceID
        FROM dbo.CampaignIndicator AS x
        JOIN dbo.CampaignNode AS a ON a.CampaignID = x.CampaignID
        JOIN dbo.IndicatorNode AS b ON b.IndicatorID = x.IndicatorID
        WHERE NOT EXISTS (SELECT 1 FROM #cur AS c WHERE c.FromKey = x.CampaignID AND c.ToKey = x.IndicatorID);

        UPDATE e SET Confidence = x.Confidence, EvidenceID = x.EvidenceID
        FROM dbo.CampaignContainsIndicator AS e
        JOIN #cur AS c ON c.EdgeID = e.$edge_id
        JOIN dbo.CampaignIndicator AS x ON x.CampaignID = c.FromKey AND x.IndicatorID = c.ToKey
        WHERE EXISTS (SELECT c.Role, c.Confidence, c.EvidenceID EXCEPT SELECT NULL, x.Confidence, x.EvidenceID);

        DROP TABLE #cur;

        /* 4.3 Türetilmiş aktör-aktör kenarı */
        EXEC dbo.sp_RefreshActorSimilarity;

        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH;
END;
GO

/* İki modelin sayıca tutarlı olduğunu doğrular: her satırda Relational = Graph olmalı */
CREATE OR ALTER PROCEDURE dbo.sp_CheckGraphConsistency
AS
BEGIN
    SET NOCOUNT ON;
    SELECT x.ObjectName, x.Kind, x.Relational, x.Graph, CAST(CASE WHEN x.Relational = x.Graph THEN 1 ELSE 0 END AS BIT) AS IsConsistent
    FROM (
        SELECT 'IndicatorNode' AS ObjectName, 'node' AS Kind, (SELECT COUNT(*) FROM dbo.Indicator) AS Relational, (SELECT COUNT(*) FROM dbo.IndicatorNode) AS Graph
        UNION ALL
        SELECT 'MalwareNode' AS ObjectName, 'node' AS Kind, (SELECT COUNT(*) FROM dbo.Malware) AS Relational, (SELECT COUNT(*) FROM dbo.MalwareNode) AS Graph
        UNION ALL
        SELECT 'ActorNode' AS ObjectName, 'node' AS Kind, (SELECT COUNT(*) FROM dbo.ThreatActor) AS Relational, (SELECT COUNT(*) FROM dbo.ActorNode) AS Graph
        UNION ALL
        SELECT 'CampaignNode' AS ObjectName, 'node' AS Kind, (SELECT COUNT(*) FROM dbo.Campaign) AS Relational, (SELECT COUNT(*) FROM dbo.CampaignNode) AS Graph
        UNION ALL
        SELECT 'TechniqueNode' AS ObjectName, 'node' AS Kind, (SELECT COUNT(*) FROM dbo.Technique) AS Relational, (SELECT COUNT(*) FROM dbo.TechniqueNode) AS Graph
        UNION ALL
        SELECT 'VulnerabilityNode' AS ObjectName, 'node' AS Kind, (SELECT COUNT(*) FROM dbo.Vulnerability) AS Relational, (SELECT COUNT(*) FROM dbo.VulnerabilityNode) AS Graph
        UNION ALL
        SELECT 'IndicatesMalware', 'edge', (SELECT COUNT(*) FROM dbo.MalwareIndicator AS x), (SELECT COUNT(*) FROM dbo.IndicatesMalware)
        UNION ALL
        SELECT 'ActorUsesMalware', 'edge', (SELECT COUNT(*) FROM dbo.ActorMalware AS x), (SELECT COUNT(*) FROM dbo.ActorUsesMalware)
        UNION ALL
        SELECT 'ActorUsesTechnique', 'edge', (SELECT COUNT(*) FROM dbo.ActorTechnique AS x), (SELECT COUNT(*) FROM dbo.ActorUsesTechnique)
        UNION ALL
        SELECT 'MalwareUsesTechnique', 'edge', (SELECT COUNT(*) FROM dbo.MalwareTechnique AS x), (SELECT COUNT(*) FROM dbo.MalwareUsesTechnique)
        UNION ALL
        SELECT 'MalwareExploitsVulnerability', 'edge', (SELECT COUNT(*) FROM dbo.MalwareVulnerability AS x), (SELECT COUNT(*) FROM dbo.MalwareExploitsVulnerability)
        UNION ALL
        SELECT 'CampaignAttributedToActor', 'edge', (SELECT COUNT(*) FROM dbo.Campaign AS x WHERE x.ActorID IS NOT NULL), (SELECT COUNT(*) FROM dbo.CampaignAttributedToActor)
        UNION ALL
        SELECT 'CampaignUsesMalware', 'edge', (SELECT COUNT(*) FROM dbo.CampaignMalware AS x), (SELECT COUNT(*) FROM dbo.CampaignUsesMalware)
        UNION ALL
        SELECT 'CampaignUsesTechnique', 'edge', (SELECT COUNT(*) FROM dbo.CampaignTechnique AS x), (SELECT COUNT(*) FROM dbo.CampaignUsesTechnique)
        UNION ALL
        SELECT 'CampaignContainsIndicator', 'edge', (SELECT COUNT(*) FROM dbo.CampaignIndicator AS x), (SELECT COUNT(*) FROM dbo.CampaignContainsIndicator)
    ) AS x
    ORDER BY x.Kind DESC, x.ObjectName;
END;
GO

/* ---------- 5. Graf sorgu yordamları ---------- */

/* Çok adımlı MATCH: bir göstergeden aktöre, aktörün kullandığı tekniklere kadar tek desen.
   gösterge -> zararlı <- aktör -> teknik */
CREATE OR ALTER PROCEDURE dbo.sp_IndicatorKillChain @IndicatorID BIGINT
AS
BEGIN
    SET NOCOUNT ON;
    SELECT m.Name AS Malware, a.Name AS Actor, t.ExternalID, t.Name AS Technique
    FROM dbo.IndicatorNode AS i_n, dbo.IndicatesMalware AS e1, dbo.MalwareNode AS m_n,
         dbo.ActorUsesMalware AS e2, dbo.ActorNode AS a_n,
         dbo.ActorUsesTechnique AS e3, dbo.TechniqueNode AS t_n,
         dbo.Malware AS m, dbo.ThreatActor AS a, dbo.Technique AS t
    WHERE MATCH(i_n-(e1)->m_n<-(e2)-a_n-(e3)->t_n)
      AND i_n.IndicatorID = @IndicatorID
      AND m.MalwareID = m_n.MalwareID AND a.ActorID = a_n.ActorID AND t.TechniqueID = t_n.TechniqueID
    ORDER BY a.Name, t.ExternalID;
END;
GO

/* SHORTEST_PATH: iki aktör arasındaki en kısa "ortak araç" zinciri.
   Ağırlıksız en kısa yoldur (adım sayısı en az olan); SharedCount yol ağırlığı olarak kullanılmaz.
   Birden çok en kısa yol varsa SQL Server bunlardan birini döndürür. */
CREATE OR ALTER PROCEDURE dbo.sp_ActorShortestPath
    @FromActorID INT,
    @ToActorID   INT,
    @MaxHops     TINYINT = 5
AS
BEGIN
    SET NOCOUNT ON;
    IF @FromActorID = @ToActorID THROW 50011, N'İki farklı aktör seçin.', 1;

    SELECT q.FromActorID, q.PathIDs, q.Hops
    FROM (
        SELECT a1.ActorID AS FromActorID,
               STRING_AGG(a2.ActorID, ',') WITHIN GROUP (GRAPH PATH) AS PathIDs,
               LAST_VALUE(a2.ActorID) WITHIN GROUP (GRAPH PATH) AS LastActorID,
               COUNT(a2.ActorID) WITHIN GROUP (GRAPH PATH) AS Hops
        FROM dbo.ActorNode AS a1,
             dbo.ActorSharesToolsWith FOR PATH AS s,
             dbo.ActorNode FOR PATH AS a2
        WHERE MATCH(SHORTEST_PATH(a1(-(s)->a2){1,6}))
          AND a1.ActorID = @FromActorID
    ) AS q
    WHERE q.LastActorID = @ToActorID AND q.Hops <= @MaxHops;
END;
GO


/* Türetilmiş aktör-aktör kenarını (en az 3 ortak yazılım) baştan hesaplar.
   Aktör-zararlı ilişkileri değişince (ATT&CK yüklemesi, arayüzden bağlama) çağrılır. */
CREATE OR ALTER PROCEDURE dbo.sp_RefreshActorSimilarity
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    BEGIN TRANSACTION;
    DELETE FROM dbo.ActorSharesToolsWith;
    INSERT INTO dbo.ActorSharesToolsWith ($from_id, $to_id, SharedCount)
    SELECT a.$node_id, b.$node_id, s.SharedCount
    FROM (
        SELECT x.ActorID AS FromActorID, y.ActorID AS ToActorID, COUNT(*) AS SharedCount
        FROM dbo.ActorMalware AS x
        JOIN dbo.ActorMalware AS y ON y.MalwareID = x.MalwareID AND y.ActorID <> x.ActorID   -- self join
        GROUP BY x.ActorID, y.ActorID
        HAVING COUNT(*) >= 3
    ) AS s
    JOIN dbo.ActorNode AS a ON a.ActorID = s.FromActorID
    JOIN dbo.ActorNode AS b ON b.ActorID = s.ToActorID;
    COMMIT TRANSACTION;
END;
GO

/* ---------- 6. Eşleme tetikleyicileri: ilişkisel değişiklik -> graf (aynı transaction) ----------
   Kenar silme, düğüm tablolarıyla $from_id/$to_id karşılaştırarak yapılır (MATCH yalnızca SELECT'te kullanılabilir). */
CREATE OR ALTER TRIGGER dbo.trg_Indicator_GraphNode ON dbo.Indicator AFTER INSERT, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE n FROM dbo.IndicatorNode AS n JOIN deleted AS d ON d.IndicatorID = n.IndicatorID;      -- kenarları ON DELETE CASCADE ile gider
    INSERT INTO dbo.IndicatorNode (IndicatorID) SELECT i.IndicatorID FROM inserted AS i
    WHERE NOT EXISTS (SELECT 1 FROM dbo.IndicatorNode AS n WHERE n.IndicatorID = i.IndicatorID);
END;
GO
-- Aynı tablodaki kenar tetikleyicisinden önce çalışmalı (önce düğüm, sonra kenar)
EXEC sp_settriggerorder @triggername = N'dbo.trg_Indicator_GraphNode', @order = N'First', @stmttype = N'INSERT';
GO
CREATE OR ALTER TRIGGER dbo.trg_Malware_GraphNode ON dbo.Malware AFTER INSERT, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE n FROM dbo.MalwareNode AS n JOIN deleted AS d ON d.MalwareID = n.MalwareID;      -- kenarları ON DELETE CASCADE ile gider
    INSERT INTO dbo.MalwareNode (MalwareID) SELECT i.MalwareID FROM inserted AS i
    WHERE NOT EXISTS (SELECT 1 FROM dbo.MalwareNode AS n WHERE n.MalwareID = i.MalwareID);
END;
GO
-- Aynı tablodaki kenar tetikleyicisinden önce çalışmalı (önce düğüm, sonra kenar)
EXEC sp_settriggerorder @triggername = N'dbo.trg_Malware_GraphNode', @order = N'First', @stmttype = N'INSERT';
GO
CREATE OR ALTER TRIGGER dbo.trg_ThreatActor_GraphNode ON dbo.ThreatActor AFTER INSERT, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE n FROM dbo.ActorNode AS n JOIN deleted AS d ON d.ActorID = n.ActorID;      -- kenarları ON DELETE CASCADE ile gider
    INSERT INTO dbo.ActorNode (ActorID) SELECT i.ActorID FROM inserted AS i
    WHERE NOT EXISTS (SELECT 1 FROM dbo.ActorNode AS n WHERE n.ActorID = i.ActorID);
END;
GO
-- Aynı tablodaki kenar tetikleyicisinden önce çalışmalı (önce düğüm, sonra kenar)
EXEC sp_settriggerorder @triggername = N'dbo.trg_ThreatActor_GraphNode', @order = N'First', @stmttype = N'INSERT';
GO
CREATE OR ALTER TRIGGER dbo.trg_Campaign_GraphNode ON dbo.Campaign AFTER INSERT, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE n FROM dbo.CampaignNode AS n JOIN deleted AS d ON d.CampaignID = n.CampaignID;      -- kenarları ON DELETE CASCADE ile gider
    INSERT INTO dbo.CampaignNode (CampaignID) SELECT i.CampaignID FROM inserted AS i
    WHERE NOT EXISTS (SELECT 1 FROM dbo.CampaignNode AS n WHERE n.CampaignID = i.CampaignID);
END;
GO
-- Aynı tablodaki kenar tetikleyicisinden önce çalışmalı (önce düğüm, sonra kenar)
EXEC sp_settriggerorder @triggername = N'dbo.trg_Campaign_GraphNode', @order = N'First', @stmttype = N'INSERT';
GO
CREATE OR ALTER TRIGGER dbo.trg_Technique_GraphNode ON dbo.Technique AFTER INSERT, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE n FROM dbo.TechniqueNode AS n JOIN deleted AS d ON d.TechniqueID = n.TechniqueID;      -- kenarları ON DELETE CASCADE ile gider
    INSERT INTO dbo.TechniqueNode (TechniqueID) SELECT i.TechniqueID FROM inserted AS i
    WHERE NOT EXISTS (SELECT 1 FROM dbo.TechniqueNode AS n WHERE n.TechniqueID = i.TechniqueID);
END;
GO
-- Aynı tablodaki kenar tetikleyicisinden önce çalışmalı (önce düğüm, sonra kenar)
EXEC sp_settriggerorder @triggername = N'dbo.trg_Technique_GraphNode', @order = N'First', @stmttype = N'INSERT';
GO
CREATE OR ALTER TRIGGER dbo.trg_Vulnerability_GraphNode ON dbo.Vulnerability AFTER INSERT, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE n FROM dbo.VulnerabilityNode AS n JOIN deleted AS d ON d.VulnerabilityID = n.VulnerabilityID;      -- kenarları ON DELETE CASCADE ile gider
    INSERT INTO dbo.VulnerabilityNode (VulnerabilityID) SELECT i.VulnerabilityID FROM inserted AS i
    WHERE NOT EXISTS (SELECT 1 FROM dbo.VulnerabilityNode AS n WHERE n.VulnerabilityID = i.VulnerabilityID);
END;
GO
-- Aynı tablodaki kenar tetikleyicisinden önce çalışmalı (önce düğüm, sonra kenar)
EXEC sp_settriggerorder @triggername = N'dbo.trg_Vulnerability_GraphNode', @order = N'First', @stmttype = N'INSERT';
GO
CREATE OR ALTER TRIGGER dbo.trg_MalwareIndicator_GraphEdge ON dbo.MalwareIndicator AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE e
    FROM dbo.IndicatesMalware AS e
    JOIN dbo.IndicatorNode AS a ON a.$node_id = e.$from_id
    JOIN dbo.MalwareNode AS b ON b.$node_id = e.$to_id
    JOIN deleted AS d ON d.IndicatorID = a.IndicatorID AND d.MalwareID = b.MalwareID;

    INSERT INTO dbo.IndicatesMalware ($from_id, $to_id, Role, Confidence, EvidenceID)
    SELECT a.$node_id, b.$node_id, i.Role, i.Confidence, i.EvidenceID
    FROM inserted AS i
    JOIN dbo.IndicatorNode AS a ON a.IndicatorID = i.IndicatorID
    JOIN dbo.MalwareNode AS b ON b.MalwareID = i.MalwareID
    WHERE 1 = 1;
END;
GO
CREATE OR ALTER TRIGGER dbo.trg_ActorMalware_GraphEdge ON dbo.ActorMalware AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE e
    FROM dbo.ActorUsesMalware AS e
    JOIN dbo.ActorNode AS a ON a.$node_id = e.$from_id
    JOIN dbo.MalwareNode AS b ON b.$node_id = e.$to_id
    JOIN deleted AS d ON d.ActorID = a.ActorID AND d.MalwareID = b.MalwareID;

    INSERT INTO dbo.ActorUsesMalware ($from_id, $to_id, Confidence, EvidenceID)
    SELECT a.$node_id, b.$node_id, i.Confidence, i.EvidenceID
    FROM inserted AS i
    JOIN dbo.ActorNode AS a ON a.ActorID = i.ActorID
    JOIN dbo.MalwareNode AS b ON b.MalwareID = i.MalwareID
    WHERE 1 = 1;
END;
GO
CREATE OR ALTER TRIGGER dbo.trg_ActorTechnique_GraphEdge ON dbo.ActorTechnique AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE e
    FROM dbo.ActorUsesTechnique AS e
    JOIN dbo.ActorNode AS a ON a.$node_id = e.$from_id
    JOIN dbo.TechniqueNode AS b ON b.$node_id = e.$to_id
    JOIN deleted AS d ON d.ActorID = a.ActorID AND d.TechniqueID = b.TechniqueID;

    INSERT INTO dbo.ActorUsesTechnique ($from_id, $to_id, Confidence, EvidenceID)
    SELECT a.$node_id, b.$node_id, i.Confidence, i.EvidenceID
    FROM inserted AS i
    JOIN dbo.ActorNode AS a ON a.ActorID = i.ActorID
    JOIN dbo.TechniqueNode AS b ON b.TechniqueID = i.TechniqueID
    WHERE 1 = 1;
END;
GO
CREATE OR ALTER TRIGGER dbo.trg_MalwareTechnique_GraphEdge ON dbo.MalwareTechnique AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE e
    FROM dbo.MalwareUsesTechnique AS e
    JOIN dbo.MalwareNode AS a ON a.$node_id = e.$from_id
    JOIN dbo.TechniqueNode AS b ON b.$node_id = e.$to_id
    JOIN deleted AS d ON d.MalwareID = a.MalwareID AND d.TechniqueID = b.TechniqueID;

    INSERT INTO dbo.MalwareUsesTechnique ($from_id, $to_id, Confidence, EvidenceID)
    SELECT a.$node_id, b.$node_id, i.Confidence, i.EvidenceID
    FROM inserted AS i
    JOIN dbo.MalwareNode AS a ON a.MalwareID = i.MalwareID
    JOIN dbo.TechniqueNode AS b ON b.TechniqueID = i.TechniqueID
    WHERE 1 = 1;
END;
GO
CREATE OR ALTER TRIGGER dbo.trg_MalwareVulnerability_GraphEdge ON dbo.MalwareVulnerability AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE e
    FROM dbo.MalwareExploitsVulnerability AS e
    JOIN dbo.MalwareNode AS a ON a.$node_id = e.$from_id
    JOIN dbo.VulnerabilityNode AS b ON b.$node_id = e.$to_id
    JOIN deleted AS d ON d.MalwareID = a.MalwareID AND d.VulnerabilityID = b.VulnerabilityID;

    INSERT INTO dbo.MalwareExploitsVulnerability ($from_id, $to_id, Confidence, EvidenceID)
    SELECT a.$node_id, b.$node_id, i.Confidence, i.EvidenceID
    FROM inserted AS i
    JOIN dbo.MalwareNode AS a ON a.MalwareID = i.MalwareID
    JOIN dbo.VulnerabilityNode AS b ON b.VulnerabilityID = i.VulnerabilityID
    WHERE 1 = 1;
END;
GO
CREATE OR ALTER TRIGGER dbo.trg_Campaign_GraphAttribution ON dbo.Campaign AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF EXISTS (SELECT 1 FROM inserted) AND EXISTS (SELECT 1 FROM deleted) AND NOT (UPDATE(ActorID) OR UPDATE(AttributionEvidenceID)) RETURN;
    DELETE e
    FROM dbo.CampaignAttributedToActor AS e
    JOIN dbo.CampaignNode AS a ON a.$node_id = e.$from_id
    JOIN dbo.ActorNode AS b ON b.$node_id = e.$to_id
    JOIN deleted AS d ON d.CampaignID = a.CampaignID AND d.ActorID = b.ActorID AND d.ActorID IS NOT NULL;

    INSERT INTO dbo.CampaignAttributedToActor ($from_id, $to_id, Confidence, EvidenceID)
    SELECT a.$node_id, b.$node_id, CAST(NULL AS TINYINT), i.AttributionEvidenceID
    FROM inserted AS i
    JOIN dbo.CampaignNode AS a ON a.CampaignID = i.CampaignID
    JOIN dbo.ActorNode AS b ON b.ActorID = i.ActorID
    WHERE 1 = 1 AND i.ActorID IS NOT NULL;
END;
GO
CREATE OR ALTER TRIGGER dbo.trg_CampaignMalware_GraphEdge ON dbo.CampaignMalware AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE e
    FROM dbo.CampaignUsesMalware AS e
    JOIN dbo.CampaignNode AS a ON a.$node_id = e.$from_id
    JOIN dbo.MalwareNode AS b ON b.$node_id = e.$to_id
    JOIN deleted AS d ON d.CampaignID = a.CampaignID AND d.MalwareID = b.MalwareID;

    INSERT INTO dbo.CampaignUsesMalware ($from_id, $to_id, Confidence, EvidenceID)
    SELECT a.$node_id, b.$node_id, i.Confidence, i.EvidenceID
    FROM inserted AS i
    JOIN dbo.CampaignNode AS a ON a.CampaignID = i.CampaignID
    JOIN dbo.MalwareNode AS b ON b.MalwareID = i.MalwareID
    WHERE 1 = 1;
END;
GO
CREATE OR ALTER TRIGGER dbo.trg_CampaignTechnique_GraphEdge ON dbo.CampaignTechnique AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE e
    FROM dbo.CampaignUsesTechnique AS e
    JOIN dbo.CampaignNode AS a ON a.$node_id = e.$from_id
    JOIN dbo.TechniqueNode AS b ON b.$node_id = e.$to_id
    JOIN deleted AS d ON d.CampaignID = a.CampaignID AND d.TechniqueID = b.TechniqueID;

    INSERT INTO dbo.CampaignUsesTechnique ($from_id, $to_id, Confidence, EvidenceID)
    SELECT a.$node_id, b.$node_id, i.Confidence, i.EvidenceID
    FROM inserted AS i
    JOIN dbo.CampaignNode AS a ON a.CampaignID = i.CampaignID
    JOIN dbo.TechniqueNode AS b ON b.TechniqueID = i.TechniqueID
    WHERE 1 = 1;
END;
GO
CREATE OR ALTER TRIGGER dbo.trg_CampaignIndicator_GraphEdge ON dbo.CampaignIndicator AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE e
    FROM dbo.CampaignContainsIndicator AS e
    JOIN dbo.CampaignNode AS a ON a.$node_id = e.$from_id
    JOIN dbo.IndicatorNode AS b ON b.$node_id = e.$to_id
    JOIN deleted AS d ON d.CampaignID = a.CampaignID AND d.IndicatorID = b.IndicatorID;

    INSERT INTO dbo.CampaignContainsIndicator ($from_id, $to_id, Confidence, EvidenceID)
    SELECT a.$node_id, b.$node_id, i.Confidence, i.EvidenceID
    FROM inserted AS i
    JOIN dbo.CampaignNode AS a ON a.CampaignID = i.CampaignID
    JOIN dbo.IndicatorNode AS b ON b.IndicatorID = i.IndicatorID
    WHERE 1 = 1;
END;
GO
