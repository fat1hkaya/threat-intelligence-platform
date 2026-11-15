/* =====================================================================
   DEMO 4 - Hatalı dosya içe aktarma: hata kaydı ve ROLLBACK
   Arayüz: Veri Kaynakları -> "Dosyadan IOC içe aktar" -> app/static/samples/ornek_hatali.csv
           "Katı mod" seçili: hatalı satırlar yüzünden geçerli satırlar da geri alınır.
           Seçili değil: geçerli satırlar yüklenir, hatalı satır ImportJobError'a yazılır.
   SSMS'te aynı akış:
   ===================================================================== */
USE ThreatLens;
GO
DECLARE @src SMALLINT = (SELECT SourceID FROM dbo.Source WHERE Name = N'Analist girişi');
DECLARE @before INT = (SELECT COUNT(*) FROM dbo.Indicator);
DECLARE @json NVARCHAR(MAX) = N'[
  {"row":1,"type":"ipv4","value":"192.0.2.201","normalized":"192.0.2.201","confidence":70},
  {"row":2,"type":"domain","value":"demo4-a.example","normalized":"demo4-a.example","confidence":70},
  {"row":3,"type":"sha256","value":"abc123","normalized":"abc123","confidence":70},
  {"row":4,"type":"ipv4","value":"192.0.2.999","normalized":"192.0.2.999","confidence":70},
  {"row":5,"type":"url","value":"hxxp://demo4-b[.]example/x","normalized":"http://demo4-b.example/x","confidence":70}
]';

-- 1) KATI MOD: hepsi ya da hiçbiri
DECLARE @job1 INT;
EXEC dbo.sp_StartImportJob @SourceID = @src, @JobType = 'file', @FileName = N'demo4.json', @IsStrict = 1;
SET @job1 = (SELECT MAX(JobID) FROM dbo.ImportJob);
EXEC dbo.sp_BulkImportIndicators @SourceID = @src, @Json = @json, @JobID = @job1, @Strict = 1;
EXEC dbo.sp_FinishImportJob @JobID = @job1;
SELECT @before AS OncekiSayi, (SELECT COUNT(*) FROM dbo.Indicator) AS SonrakiSayi;   -- değişmemeli
SELECT RowNo, RawValue, Reason FROM dbo.ImportJobError WHERE JobID = @job1 ORDER BY RowNo;   -- satır 3 ve 4

-- 2) ESNEK MOD: geçerliler yüklenir, hatalılar raporlanır
DECLARE @job2 INT;
EXEC dbo.sp_StartImportJob @SourceID = @src, @JobType = 'file', @FileName = N'demo4.json', @IsStrict = 0;
SET @job2 = (SELECT MAX(JobID) FROM dbo.ImportJob);
EXEC dbo.sp_BulkImportIndicators @SourceID = @src, @Json = @json, @JobID = @job2, @Strict = 0;
EXEC dbo.sp_FinishImportJob @JobID = @job2;   -- durum: partial, 3 eklendi, 2 hatalı
SELECT @before AS OncekiSayi, (SELECT COUNT(*) FROM dbo.Indicator) AS SonrakiSayi;   -- 3 artmalı

-- Temizlik: DELETE FROM dbo.Indicator WHERE NormalizedValue IN (N'192.0.2.201', N'demo4-a.example', N'http://demo4-b.example/x');
