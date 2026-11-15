/* =====================================================================
   ThreatLens - 11: SQL Server Agent zamanlanmış işleri (msdb)
   Tekrar çalıştırılabilir: aynı adlı iş varsa silinip yeniden oluşturulur.
   Express sürümünde Agent yoktur; bu durumda betik uyarı verip geçer.
     1) ThreatLens - Süresi dolan IOC'ler   : her gece 02:00  -> EXEC dbo.sp_ExpireIndicators
     2) ThreatLens - Graf bakımı             : her pazar 03:00 -> EXEC dbo.sp_GraphMaintenance
   İş geçmişi: SSMS -> SQL Server Agent -> Jobs -> sağ tık -> View History
   Elle çalıştırma: EXEC msdb.dbo.sp_start_job @job_name = N'ThreatLens - Süresi dolan IOC''ler';
   Not: İnternetten besleme çekme işi Python'dadır ve Windows Görev Zamanlayıcı ile çalışır
   (scripts/sync_feeds.cmd); Agent hizmet hesabı kullanıcı klasöründeki Python ortamına erişemez.
   ===================================================================== */
USE msdb;
GO
IF SERVERPROPERTY('EngineEdition') = 4   -- Express
BEGIN
    PRINT N'SQL Server Express: Agent yok, zamanlanmış işler oluşturulmadı. sp_ExpireIndicators elle çalıştırılabilir.';
    RETURN;
END;

DECLARE @jobs TABLE (Name SYSNAME, Command NVARCHAR(400), FreqType INT, FreqInterval INT, StartTime INT, Descr NVARCHAR(400));
INSERT INTO @jobs VALUES
    (N'ThreatLens - Süresi dolan IOC''ler', N'EXEC dbo.sp_ExpireIndicators;', 4, 1, 20000,
     N'Geçerlilik süresi (RetentionPolicy) dolan aktif IOC''leri pasife alır. Sonuç: dbo.MaintenanceRun.'),
    (N'ThreatLens - Graf bakımı', N'EXEC dbo.sp_GraphMaintenance;', 8, 1, 30000,
     N'Aktör benzerlik kenarlarını yeniler, ilişkisel model ile SQL Graph''ı karşılaştırır, tutarsızlıkta sp_SyncGraph çalıştırır.');

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
         @database_name = N'ThreatLens', @command = @cmd, @retry_attempts = 1, @retry_interval = 5;
    -- freq_type 4 = günlük (her @fi günde), 8 = haftalık (@fi bit maskesi: 1 = pazar)
    EXEC msdb.dbo.sp_add_jobschedule @job_id = @jobId, @name = @name, @enabled = 1, @freq_type = @ft, @freq_interval = @fi,
         @freq_recurrence_factor = 1, @active_start_time = @st;
    EXEC msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)';
    FETCH NEXT FROM c INTO @name, @cmd, @ft, @fi, @st, @descr;
END;
CLOSE c; DEALLOCATE c;

SELECT j.name AS IsAdi, j.enabled AS Etkin, s.next_run_date AS SonrakiTarih, s.next_run_time AS SonrakiSaat
FROM msdb.dbo.sysjobs AS j LEFT JOIN msdb.dbo.sysjobschedules AS s ON s.job_id = j.job_id
WHERE j.name LIKE N'ThreatLens - %';
GO
USE ThreatLens;
GO
