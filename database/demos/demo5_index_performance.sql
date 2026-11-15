/* =====================================================================
   DEMO 5 - İndeksli ve indekssiz sorgu karşılaştırması
   Demo verisi küçük olduğu için farkı görünür kılmak amacıyla 500.000 satırlık
   geçici bir kopya tablo üretilir. SSMS'te "Include Actual Execution Plan" (Ctrl+M)
   açıkken çalıştırın; Messages sekmesinde logical reads ve CPU süresini karşılaştırın.
   ===================================================================== */
USE ThreatLens;
GO
DROP TABLE IF EXISTS dbo.PerfIndicator;
-- 500.000 satır: sayı tablosu iki sys.all_objects çaprazından üretilir
SELECT TOP (500000)
       ISNULL(CAST(ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS INT), 0) AS ID,   -- ISNULL: sütun NOT NULL olsun (PK için)
       CAST(CONCAT(N'host-', ROW_NUMBER() OVER (ORDER BY (SELECT NULL)), N'.perf.example') AS NVARCHAR(400)) AS NormalizedValue,
       CAST(ABS(CHECKSUM(NEWID())) % 101 AS TINYINT) AS Confidence
INTO dbo.PerfIndicator
FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b;
GO
-- Yeni tablo ayrı yığında değiştirilir (aynı yığında derlenirse SELECT INTO'nun sütun tanımı henüz bilinmez)
ALTER TABLE dbo.PerfIndicator ADD CONSTRAINT PK_PerfIndicator PRIMARY KEY (ID);
GO
SET STATISTICS IO ON;
SET STATISTICS TIME ON;

-- 1) İndekssiz: Clustered Index Scan, ~ tüm sayfalar okunur
SELECT ID, Confidence FROM dbo.PerfIndicator WHERE NormalizedValue = N'host-424242.perf.example';

-- 2) İndeks ekle
CREATE NONCLUSTERED INDEX IX_PerfIndicator_Value ON dbo.PerfIndicator (NormalizedValue) INCLUDE (Confidence);

-- 3) İndeksli: Index Seek, birkaç sayfa okunur
SELECT ID, Confidence FROM dbo.PerfIndicator WHERE NormalizedValue = N'host-424242.perf.example';

-- 4) Aralık sorgusunda indeks kullanılmaz: önde joker (LIKE '%...') -> Index Scan
SELECT COUNT(*) FROM dbo.PerfIndicator WHERE NormalizedValue LIKE N'%42424%';

SET STATISTICS IO OFF;
SET STATISTICS TIME OFF;
-- Beklenen: (1) logical reads binlerce, (3) logical reads 3-4. Rapor için iki planın ekran görüntüsünü alın.
DROP TABLE dbo.PerfIndicator;
