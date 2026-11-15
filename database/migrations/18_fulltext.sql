/* =====================================================================
   ThreatLens - 18: Tam metin arama (Full-Text Search)
   Tekrar çalıştırılabilir. Full-Text bileşeni kurulu değilse (ör. SQL Express) atlanır; uygulama
   aramayı LIKE ile yapar.
   ---------------------------------------------------------------------
   LIKE '%kelime%' her satırı tarar ve "phishing" ararken "phished" bulmaz. Tam metin dizini kelimeleri
   ters dizinde tutar; FREETEXTTABLE çekim eklerini/kök biçimleri de eşleştirir ve alaka puanı (RANK) verir.
   Dizinlenen metinler (İngilizce, LCID 1033: ATT&CK ve Malpedia kaynaklı):
     ThreatActor.Description, Malware.Description, Campaign.Description, Technique.Name/Description,
     Evidence.Summary (~20.000 ilişki kanıtı)
   Değişiklik izleme AUTO: yeni/değişen satırlar dizine kendiliğinden eklenir.
   ===================================================================== */
USE ThreatLens;
GO
IF FULLTEXTSERVICEPROPERTY('IsFulltextInstalled') = 1
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.fulltext_catalogs WHERE name = N'ThreatLensCatalog')
        EXEC(N'CREATE FULLTEXT CATALOG ThreatLensCatalog AS DEFAULT;');
    IF NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'dbo.ThreatActor'))
        EXEC(N'CREATE FULLTEXT INDEX ON dbo.ThreatActor (Name LANGUAGE 1033, Description LANGUAGE 1033) KEY INDEX PK_ThreatActor WITH CHANGE_TRACKING AUTO;');
    IF NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'dbo.Malware'))
        EXEC(N'CREATE FULLTEXT INDEX ON dbo.Malware (Name LANGUAGE 1033, Description LANGUAGE 1033) KEY INDEX PK_Malware WITH CHANGE_TRACKING AUTO;');
    IF NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'dbo.Campaign'))
        EXEC(N'CREATE FULLTEXT INDEX ON dbo.Campaign (Name LANGUAGE 1033, Description LANGUAGE 1033) KEY INDEX PK_Campaign WITH CHANGE_TRACKING AUTO;');
    IF NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'dbo.Technique'))
        EXEC(N'CREATE FULLTEXT INDEX ON dbo.Technique (Name LANGUAGE 1033, Description LANGUAGE 1033) KEY INDEX PK_Technique WITH CHANGE_TRACKING AUTO;');
    IF NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'dbo.Evidence'))
        EXEC(N'CREATE FULLTEXT INDEX ON dbo.Evidence (Summary LANGUAGE 1033) KEY INDEX PK_Evidence WITH CHANGE_TRACKING AUTO;');
END
ELSE
    PRINT N'Full-Text Search kurulu değil: tam metin dizinleri oluşturulmadı (arama LIKE ile yapılır).';
GO

/* Tam metin araması: varlık açıklamaları ve kanıt metinleri, alaka puanına göre.
   Yordam FREETEXTTABLE kullandığı için yalnızca Full-Text kuruluysa oluşturulur. */
IF FULLTEXTSERVICEPROPERTY('IsFulltextInstalled') = 1
    EXEC(N'CREATE OR ALTER PROCEDURE dbo.sp_TextSearch @Query NVARCHAR(200), @Top INT = 8
AS
BEGIN
    SET NOCOUNT ON;
    -- 1) Varlıklar: ad ve açıklamada anlam/çekim eki duyarlı arama (FREETEXTTABLE + RANK)
    SELECT TOP (@Top * 2) x.EntityType, x.EntityID, x.Title, x.Sub, x.Rnk, x.Snippet
    FROM (
        SELECT ''actor'' AS EntityType, CAST(a.ActorID AS BIGINT) AS EntityID, a.Name AS Title, a.ExternalID AS Sub, k.[RANK] AS Rnk, LEFT(a.Description, 240) AS Snippet
        FROM FREETEXTTABLE(dbo.ThreatActor, (Name, Description), @Query, LANGUAGE 1033, @Top) AS k JOIN dbo.ThreatActor AS a ON a.ActorID = k.[KEY]
        UNION ALL
        SELECT ''malware'', m.MalwareID, m.Name, m.ExternalID, k.[RANK], LEFT(m.Description, 240)
        FROM FREETEXTTABLE(dbo.Malware, (Name, Description), @Query, LANGUAGE 1033, @Top) AS k JOIN dbo.Malware AS m ON m.MalwareID = k.[KEY]
        UNION ALL
        SELECT ''campaign'', c.CampaignID, c.Name, c.ExternalID, k.[RANK], LEFT(c.Description, 240)
        FROM FREETEXTTABLE(dbo.Campaign, (Name, Description), @Query, LANGUAGE 1033, @Top) AS k JOIN dbo.Campaign AS c ON c.CampaignID = k.[KEY]
        UNION ALL
        SELECT ''technique'', t.TechniqueID, t.Name, t.ExternalID, k.[RANK], LEFT(t.Description, 240)
        FROM FREETEXTTABLE(dbo.Technique, (Name, Description), @Query, LANGUAGE 1033, @Top) AS k JOIN dbo.Technique AS t ON t.TechniqueID = k.[KEY]
    ) AS x
    ORDER BY x.Rnk DESC;

    -- 2) Kanıt metinleri: hangi ilişkiye ait olduğu ara tablolardan bulunur
    SELECT TOP (@Top) e.EvidenceID, k.[RANK] AS Rnk, LEFT(e.Summary, 300) AS Summary, s.Name AS SourceName, e.Url,
           r.RelType, r.AID, r.AName, r.BType, r.BID, r.BName
    FROM FREETEXTTABLE(dbo.Evidence, Summary, @Query, LANGUAGE 1033, 60) AS k
    JOIN dbo.Evidence AS e ON e.EvidenceID = k.[KEY]
    JOIN dbo.Source AS s ON s.SourceID = e.SourceID
    OUTER APPLY (
        SELECT TOP (1) q.RelType, q.AID, q.AName, q.BType, q.BID, q.BName FROM (
            SELECT ''actor-technique'' AS RelType, x.ActorID AS AID, a.Name AS AName, ''technique'' AS BType, CAST(x.TechniqueID AS BIGINT) AS BID, t.ExternalID + N'' '' + t.Name AS BName
            FROM dbo.ActorTechnique AS x JOIN dbo.ThreatActor AS a ON a.ActorID = x.ActorID JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID WHERE x.EvidenceID = e.EvidenceID
            UNION ALL
            SELECT ''actor-malware'', x.ActorID, a.Name, ''malware'', x.MalwareID, m.Name
            FROM dbo.ActorMalware AS x JOIN dbo.ThreatActor AS a ON a.ActorID = x.ActorID JOIN dbo.Malware AS m ON m.MalwareID = x.MalwareID WHERE x.EvidenceID = e.EvidenceID
            UNION ALL
            SELECT ''malware-technique'', x.MalwareID, m.Name, ''technique'', x.TechniqueID, t.ExternalID + N'' '' + t.Name
            FROM dbo.MalwareTechnique AS x JOIN dbo.Malware AS m ON m.MalwareID = x.MalwareID JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID WHERE x.EvidenceID = e.EvidenceID
            UNION ALL
            SELECT ''campaign-technique'', x.CampaignID, c.Name, ''technique'', x.TechniqueID, t.ExternalID + N'' '' + t.Name
            FROM dbo.CampaignTechnique AS x JOIN dbo.Campaign AS c ON c.CampaignID = x.CampaignID JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID WHERE x.EvidenceID = e.EvidenceID
        ) AS q
    ) AS r
    ORDER BY k.[RANK] DESC;
END;');
GO
IF OBJECT_ID(N'dbo.sp_TextSearch') IS NOT NULL
    GRANT EXECUTE ON dbo.sp_TextSearch TO tip_reader;
GO
