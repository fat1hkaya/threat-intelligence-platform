/* =====================================================================
   ThreatLens - Yedekleme ve geri yükleme senaryosu
   Yollar sunucunun kendi varsayılan klasörlerinden alınır (SERVERPROPERTY):
   SQL Server hizmet hesabının bu klasörlere yazma izni zaten vardır.
   Farklı bir klasör kullanacaksanız @dir değişkenini değiştirin (ör. N'C:\SQLBackup\').
   ===================================================================== */
USE master;
GO
DECLARE @dir  NVARCHAR(400) = CAST(SERVERPROPERTY('InstanceDefaultBackupPath') AS NVARCHAR(400));
DECLARE @data NVARCHAR(400) = CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS NVARCHAR(400));
IF RIGHT(@dir, 1) <> N'\' SET @dir += N'\';
IF RIGHT(@data, 1) <> N'\' SET @data += N'\';
DECLARE @bak NVARCHAR(500) = @dir + N'ThreatLens_full.bak';
SELECT @bak AS YedekDosyasi, @data AS VeriKlasoru;

-- 1) Tam yedek (sağlama toplamlı). COMPRESSION, Express sürümünde desteklenmez; Developer/Standard'da çalışır.
BACKUP DATABASE ThreatLens TO DISK = @bak
WITH FORMAT, INIT, COMPRESSION, CHECKSUM, NAME = N'ThreatLens tam yedek';

-- 2) Yedek dosyası okunabilir mi?
RESTORE VERIFYONLY FROM DISK = @bak WITH CHECKSUM;

-- 3) Yedeğin içindeki dosyaların mantıksal adları (MOVE için gerekir)
RESTORE FILELISTONLY FROM DISK = @bak;

-- 4) Felaket senaryosu: bir gösterge yanlışlıkla silindi. Canlı veritabanına dokunmadan
--    yedeği AYRI bir adla geri yükleyip kaybolan satırı oradan kurtarın.
DECLARE @mdf NVARCHAR(500) = @data + N'ThreatLens_Restore.mdf', @ldf NVARCHAR(500) = @data + N'ThreatLens_Restore_log.ldf';
RESTORE DATABASE ThreatLens_Restore FROM DISK = @bak
WITH MOVE N'ThreatLens' TO @mdf, MOVE N'ThreatLens_log' TO @ldf, REPLACE, RECOVERY;

-- Geri yüklenen kopyada satır sayıları canlı veritabanıyla aynı olmalı
SELECT (SELECT COUNT(*) FROM ThreatLens.dbo.Indicator) AS CanliIOC,
       (SELECT COUNT(*) FROM ThreatLens_Restore.dbo.Indicator) AS YedektekiIOC,
       (SELECT COUNT(*) FROM ThreatLens_Restore.dbo.IndicatorNode) AS YedektekiIOCDugumu;
GO
-- 5) Kurtarma: yedekte olup canlıda olmayan göstergeleri geri ekle
--    (IDENTITY_INSERT ile aynı kimlik korunur; graf düğümü tetikleyiciyle oluşur)
/*
SET IDENTITY_INSERT ThreatLens.dbo.Indicator ON;
INSERT INTO ThreatLens.dbo.Indicator (IndicatorID, TypeID, Value, NormalizedValue, Confidence, SeverityID, TLPID, SourceID, Status,
                                      Description, FirstSeen, LastSeen, ExpiresAt, CreatedBy, CreatedAt, UpdatedAt)
SELECT r.IndicatorID, r.TypeID, r.Value, r.NormalizedValue, r.Confidence, r.SeverityID, r.TLPID, r.SourceID, r.Status,
       r.Description, r.FirstSeen, r.LastSeen, r.ExpiresAt, r.CreatedBy, r.CreatedAt, r.UpdatedAt
FROM ThreatLens_Restore.dbo.Indicator AS r
WHERE NOT EXISTS (SELECT 1 FROM ThreatLens.dbo.Indicator AS l WHERE l.IndicatorID = r.IndicatorID);
SET IDENTITY_INSERT ThreatLens.dbo.Indicator OFF;
*/
-- 6) Temizlik: geri yükleme kopyasını kaldır
DROP DATABASE IF EXISTS ThreatLens_Restore;
GO
-- Not: Kurtarma modeli FULL ise işlem günlüğü yedeğiyle belirli bir ana dönülebilir (point-in-time):
-- ALTER DATABASE ThreatLens SET RECOVERY FULL;
-- BACKUP LOG ThreatLens TO DISK = N'...\ThreatLens_log.trn';
-- RESTORE DATABASE ... WITH NORECOVERY;  RESTORE LOG ... WITH STOPAT = '2026-12-17T10:30:00', RECOVERY;
