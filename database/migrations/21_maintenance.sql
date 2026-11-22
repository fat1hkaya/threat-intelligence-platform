/* =====================================================================
   ThreatLens - 21: Veritabanı bakımı (kurtarma modeli, yedekleme, bütünlük denetimi)
   Tekrar çalıştırılabilir.
   ---------------------------------------------------------------------
   Sorun: veritabanı model veritabanından FULL kurtarma modelini almıştı ama hiç log yedeği
   alınmıyordu. FULL modelde log yalnızca LOG yedeğiyle boşalır; beslemeler her 6 saatte bir
   on binlerce satır yazdığı için log dosyası 136 MB veriye karşılık 3,9 GB'a çıktı.
   Karar: SIMPLE kurtarma modeli + her gece tam yedek.
     - SIMPLE: log her CHECKPOINT'te kendini yeniden kullanır, büyümez. Kaybedilebilecek en çok veri
       son gecelik yedekten sonrasıdır; beslemeler yeniden çekilebildiği için bu kabul edilebilir.
     - Zamana dönük geri yükleme (point-in-time) gerekirse: FULL'a geçilir ve log yedeği işi eklenir
       (database/backup/backup_restore.sql sonundaki notlar).
   Yedekler: haftanın günü başına bir dosya (ThreatLens_gun1..7.bak), WITH INIT ile üzerine yazılır:
   disk kullanımı en çok 7 yedekle sınırlı, ayrıca dosya silme işi gerekmez.
   Bütünlük: her pazar DBCC CHECKDB. Sonuçlar dbo.MaintenanceRun tablosundadır (Ayarlar ekranı).
   ===================================================================== */
USE ThreatLens;
GO

/* 1) Kurtarma modeli ve log boyutu */
IF (SELECT recovery_model_desc FROM sys.databases WHERE name = DB_NAME()) <> 'SIMPLE'
    ALTER DATABASE CURRENT SET RECOVERY SIMPLE;
GO
CHECKPOINT;
GO
-- Log 1 GB'tan büyükse bir kez küçültülür (düzenli küçültme önerilmez; büyüme nedeni ortadan kalktı)
IF EXISTS (SELECT 1 FROM sys.database_files WHERE type_desc = 'LOG' AND size * 8 / 1024 > 1024)
BEGIN
    DECLARE @log SYSNAME = (SELECT name FROM sys.database_files WHERE type_desc = 'LOG');
    DBCC SHRINKFILE (@log, 256) WITH NO_INFOMSGS;
END;
GO

/* 2) Gecelik tam yedek (haftanın günü başına dönen dosya) */
CREATE OR ALTER PROCEDURE dbo.sp_BackupDatabase @Folder NVARCHAR(260) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @run INT, @path NVARCHAR(400), @dir NVARCHAR(260) = COALESCE(@Folder, CAST(SERVERPROPERTY('InstanceDefaultBackupPath') AS NVARCHAR(260)));
    IF RIGHT(@dir, 1) NOT IN (N'\', N'/') SET @dir += N'\';
    -- DATEPART(WEEKDAY) DATEFIRST ayarına bağlıdır; sabit bir tarihten gün farkı dilden bağımsızdır (1 = pazartesi)
    SET @path = CONCAT(@dir, N'ThreatLens_gun', DATEDIFF(DAY, '20000103', SYSDATETIME()) % 7 + 1, N'.bak');
    INSERT INTO dbo.MaintenanceRun (Task) VALUES ('backup-full');
    SET @run = SCOPE_IDENTITY();
    BEGIN TRY
        BACKUP DATABASE ThreatLens TO DISK = @path WITH INIT, FORMAT, CHECKSUM, COMPRESSION, STATS = 100,
             NAME = N'ThreatLens gecelik tam yedek';
        RESTORE VERIFYONLY FROM DISK = @path WITH CHECKSUM;
        UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), Status = 'success',
               RowsAffected = (SELECT TOP (1) CAST(compressed_backup_size / 1048576 AS INT) FROM msdb.dbo.backupset
                               WHERE database_name = N'ThreatLens' ORDER BY backup_finish_date DESC),
               Message = LEFT(CONCAT(N'Yedek doğrulandı (MB = RowsAffected): ', @path), 400)
        WHERE RunID = @run;
    END TRY
    BEGIN CATCH
        UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), Status = 'failed', Message = LEFT(ERROR_MESSAGE(), 400) WHERE RunID = @run;
        THROW;
    END CATCH;
END;
GO

/* 3) Haftalık bütünlük denetimi */
CREATE OR ALTER PROCEDURE dbo.sp_CheckIntegrity
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @run INT;
    INSERT INTO dbo.MaintenanceRun (Task) VALUES ('checkdb');
    SET @run = SCOPE_IDENTITY();
    BEGIN TRY
        DBCC CHECKDB (ThreatLens) WITH NO_INFOMSGS, ALL_ERRORMSGS;   -- bozulma varsa hata fırlatır
        UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), Status = 'success', Message = N'DBCC CHECKDB: tutarsızlık yok'
        WHERE RunID = @run;
    END TRY
    BEGIN CATCH
        UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), Status = 'failed', Message = LEFT(ERROR_MESSAGE(), 400) WHERE RunID = @run;
        THROW;
    END CATCH;
END;
GO

/* 4) Agent işleri */
USE msdb;
GO
IF SERVERPROPERTY('EngineEdition') <> 4      -- Express'te Agent yok
BEGIN
    DECLARE @jobs TABLE (Name SYSNAME, Command NVARCHAR(400), FreqType INT, FreqInterval INT, StartTime INT, Descr NVARCHAR(400));
    INSERT INTO @jobs VALUES
        (N'ThreatLens - Gecelik yedek', N'EXEC dbo.sp_BackupDatabase;', 4, 1, 10000,
         N'Her gece 01:00 sıkıştırılmış ve doğrulanmış tam yedek; haftanın her günü için ayrı dosya (7 yedek döner).'),
        (N'ThreatLens - Bütünlük denetimi', N'EXEC dbo.sp_CheckIntegrity;', 8, 1, 40000,
         N'Her pazar 04:00 DBCC CHECKDB. Sonuç: dbo.MaintenanceRun.');
    DECLARE @name SYSNAME, @cmd NVARCHAR(400), @ft INT, @fi INT, @st INT, @descr NVARCHAR(400), @jobId UNIQUEIDENTIFIER;
    DECLARE c CURSOR LOCAL FAST_FORWARD FOR SELECT Name, Command, FreqType, FreqInterval, StartTime, Descr FROM @jobs;
    OPEN c;
    FETCH NEXT FROM c INTO @name, @cmd, @ft, @fi, @st, @descr;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = @name)
            EXEC msdb.dbo.sp_delete_job @job_name = @name, @delete_unused_schedule = 1;
        SET @jobId = NULL;
        EXEC msdb.dbo.sp_add_job @job_name = @name, @description = @descr, @enabled = 1, @job_id = @jobId OUTPUT;
        EXEC msdb.dbo.sp_add_jobstep @job_id = @jobId, @step_name = N'Çalıştır', @subsystem = N'TSQL',
             @database_name = N'ThreatLens', @command = @cmd, @retry_attempts = 1, @retry_interval = 10;
        EXEC msdb.dbo.sp_add_jobschedule @job_id = @jobId, @name = @name, @enabled = 1, @freq_type = @ft, @freq_interval = @fi,
             @freq_recurrence_factor = 1, @active_start_time = @st;
        EXEC msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)';
        FETCH NEXT FROM c INTO @name, @cmd, @ft, @fi, @st, @descr;
    END;
    CLOSE c; DEALLOCATE c;
END;
GO
USE ThreatLens;
GO
