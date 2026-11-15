/* =====================================================================
   DEMO 8 - İleri veritabanı özellikleri
   SSMS'te "Include Actual Execution Plan" (Ctrl+M) açıkken çalıştırın; Messages sekmesinde
   STATISTICS IO/TIME çıktısını (logical reads, CPU süresi) karşılaştırın.
     1) Tam metin arama  : LIKE '%...%' (her satırı tarar) <-> CONTAINS / FREETEXTTABLE (ters dizin)
     2) Indexed view     : COUNT(*) GROUP BY (tablo taraması) <-> vw_IndicatorCounts WITH (NOEXPAND)
     3) Columnstore      : AuditLog analitik sorgusu, columnstore'lu ve columnstore'suz
     4) Temporal tables  : bir IOC'nin tüm sürümleri ve geçmişteki bir anda hâli
     5) Query Store      : en pahalı sorgular
   ===================================================================== */
USE ThreatLens;
GO
SET STATISTICS IO ON;
SET STATISTICS TIME ON;

-- 1) Tam metin arama. LIKE alt dize arar ("spearphishing" içindeki "phish"i de bulur) ve indeks kullanamaz.
SELECT COUNT(*) AS LikeSonuc FROM dbo.Evidence WHERE Summary LIKE N'%phish%';
IF FULLTEXTSERVICEPROPERTY('IsFulltextInstalled') = 1
BEGIN
    -- Kelime biçimleri: phish, phished, phishing ...
    EXEC(N'SELECT COUNT(*) AS ContainsSonuc FROM dbo.Evidence WHERE CONTAINS(Summary, N''FORMSOF(INFLECTIONAL, phish)'');');
    -- Anlam/alaka sıralı arama
    EXEC(N'SELECT TOP (5) k.[RANK], LEFT(e.Summary, 120) AS Kanit
          FROM FREETEXTTABLE(dbo.Evidence, Summary, N''spearphishing government ministries'') AS k
          JOIN dbo.Evidence AS e ON e.EvidenceID = k.[KEY] ORDER BY k.[RANK] DESC;');
END;

-- 2) Indexed view: aynı soru iki yoldan. İkincisi önceden toplanmış birkaç satırı okur.
SELECT Status, COUNT(*) AS Toplam FROM dbo.Indicator GROUP BY Status;
SELECT Status, SUM(Total) AS Toplam FROM dbo.vw_IndicatorCounts WITH (NOEXPAND) GROUP BY Status;

-- 3) Columnstore: günlük denetim olayı sayısı. İkinci sorgu columnstore indeksini kullanmamaya zorlanır.
SELECT CAST(ChangedAt AS DATE) AS Gun, TableName, Action, COUNT(*) AS Olay
FROM dbo.AuditLog GROUP BY CAST(ChangedAt AS DATE), TableName, Action;
SELECT CAST(ChangedAt AS DATE) AS Gun, TableName, Action, COUNT(*) AS Olay
FROM dbo.AuditLog GROUP BY CAST(ChangedAt AS DATE), TableName, Action
OPTION (IGNORE_NONCLUSTERED_COLUMNSTORE_INDEX);

SET STATISTICS IO OFF;
SET STATISTICS TIME OFF;

-- 4) Temporal: en çok sürümü olan IOC'nin geçmişi ve 1 saat önceki hâli
DECLARE @id BIGINT = (SELECT TOP (1) IndicatorID FROM dbo.Indicator FOR SYSTEM_TIME ALL GROUP BY IndicatorID ORDER BY COUNT(*) DESC);
EXEC dbo.sp_IndicatorVersions @IndicatorID = @id;
DECLARE @t DATETIME2(3) = DATEADD(HOUR, -1, SYSUTCDATETIME());
EXEC dbo.sp_IndicatorAsOf @IndicatorID = @id, @AsOf = @t;
EXEC dbo.sp_IndicatorStatsAsOf @AsOf = @t;

-- 5) Query Store
EXEC dbo.sp_TopQueries @Top = 5;
