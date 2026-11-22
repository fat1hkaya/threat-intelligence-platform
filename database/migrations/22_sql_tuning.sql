/* =====================================================================
   ThreatLens - 22: Yabancı anahtar indeksleri, geçmiş temizliği, satır sürümlemeli okuma
   Tekrar çalıştırılabilir.
   ---------------------------------------------------------------------
   1) Yabancı anahtar indeksleri
      SQL Server yabancı anahtar sütununa kendiliğinden indeks açmaz. Üst kayıt silinirken ya da
      güncellenirken (ör. bir Evidence satırı silinince 8 ilişki tablosunda EvidenceID = NULL yapılır)
      alt tablolar baştan sona taranır. İndeks eklenenler: silinen/değişen üst kaydı olan ve
      JOIN'lerde kullanılan sütunlar. Eklenmeyenler: birkaç satırlık sözlük tablolarına (SeverityLevel,
      TLPLevel, Role, MalwareType, Motivation) giden sütunlar: bu tablolardan kayıt silinmez ve
      seçicilik düşüktür; indeks yalnızca yazma maliyeti getirirdi.
      EvidenceID boş (NULL) olabildiği için indeksler filtrelidir (WHERE EvidenceID IS NOT NULL).
   2) Geçmiş temizliği (sp_PurgeHistory, her pazar): giriş denemeleri 90 gün, süresi dolmuş oturumlar,
      içe aktarma işleri ve log avları 365 gün, bakım kayıtları 180 gün tutulur.
      AuditLog temizlenmez: denetim izi değiştirilemez ve silinemez (trg_AuditLog_Protect).
   3) READ_COMMITTED_SNAPSHOT: okuyucular yazarları, yazarlar okuyucuları beklemez; READ COMMITTED
      okuması son onaylanmış satır sürümünü (tempdb sürüm deposundan) döndürür. Besleme içe aktarımı
      sürerken gösterge paneli ve listeler bloklanmaz. Klasik kilitli okuma isteyen sorgu
      WITH (READCOMMITTEDLOCK) ipucunu kullanır (demo6).
   ===================================================================== */
USE ThreatLens;
GO

/* 1) Yabancı anahtar indeksleri */
DECLARE @ix TABLE (TableName SYSNAME, IndexName SYSNAME, Ddl NVARCHAR(400));
INSERT INTO @ix VALUES
    (N'ActorMalware',         N'IX_ActorMalware_Evidence',         N'(EvidenceID) WHERE EvidenceID IS NOT NULL'),
    (N'ActorTechnique',       N'IX_ActorTechnique_Evidence',       N'(EvidenceID) WHERE EvidenceID IS NOT NULL'),
    (N'MalwareTechnique',     N'IX_MalwareTechnique_Evidence',     N'(EvidenceID) WHERE EvidenceID IS NOT NULL'),
    (N'MalwareVulnerability', N'IX_MalwareVulnerability_Evidence', N'(EvidenceID) WHERE EvidenceID IS NOT NULL'),
    (N'MalwareIndicator',     N'IX_MalwareIndicator_Evidence',     N'(EvidenceID) WHERE EvidenceID IS NOT NULL'),
    (N'CampaignMalware',      N'IX_CampaignMalware_Evidence',      N'(EvidenceID) WHERE EvidenceID IS NOT NULL'),
    (N'CampaignTechnique',    N'IX_CampaignTechnique_Evidence',    N'(EvidenceID) WHERE EvidenceID IS NOT NULL'),
    (N'CampaignIndicator',    N'IX_CampaignIndicator_Evidence',    N'(EvidenceID) WHERE EvidenceID IS NOT NULL'),
    (N'Campaign',             N'IX_Campaign_AttributionEvidence',  N'(AttributionEvidenceID) WHERE AttributionEvidenceID IS NOT NULL'),
    (N'Investigation',        N'IX_Investigation_AssignedTo',      N'(AssignedTo, Status) WHERE AssignedTo IS NOT NULL'),
    (N'Investigation',        N'IX_Investigation_CreatedBy',       N'(CreatedBy) WHERE CreatedBy IS NOT NULL'),
    (N'InvestigationNote',    N'IX_InvestigationNote_Author',      N'(AuthorID) WHERE AuthorID IS NOT NULL'),
    (N'Sighting',             N'IX_Sighting_ReportedBy',           N'(ReportedBy) WHERE ReportedBy IS NOT NULL'),
    (N'Sighting',             N'IX_Sighting_SightedAt',            N'(SightedAt) INCLUDE (IndicatorID)'),
    (N'LoginAttempt',         N'IX_LoginAttempt_User',             N'(UserID) WHERE UserID IS NOT NULL'),
    (N'HuntRun',              N'IX_HuntRun_StartedBy',             N'(StartedBy) WHERE StartedBy IS NOT NULL'),
    (N'ImportJob',            N'IX_ImportJob_StartedBy',           N'(StartedBy) WHERE StartedBy IS NOT NULL'),
    (N'Indicator',            N'IX_Indicator_CreatedBy',           N'(CreatedBy) WHERE CreatedBy IS NOT NULL'),
    (N'ActorTargetSector',    N'IX_ActorTargetSector_Sector',      N'(SectorID)'),
    (N'ActorTargetCountry',   N'IX_ActorTargetCountry_Country',    N'(CountryCode)'),
    (N'ThreatActor',          N'IX_ThreatActor_Country',           N'(CountryCode) WHERE CountryCode IS NOT NULL'),
    (N'IpRange',              N'IX_IpRange_ASN',                   N'(ASN)');
DECLARE @t SYSNAME, @n SYSNAME, @d NVARCHAR(400), @sql NVARCHAR(800);
DECLARE c CURSOR LOCAL FAST_FORWARD FOR SELECT TableName, IndexName, Ddl FROM @ix;
OPEN c; FETCH NEXT FROM c INTO @t, @n, @d;
WHILE @@FETCH_STATUS = 0
BEGIN
    IF OBJECT_ID(N'dbo.' + @t) IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID(N'dbo.' + @t) AND name = @n)
    BEGIN
        SET @sql = N'CREATE INDEX ' + QUOTENAME(@n) + N' ON dbo.' + QUOTENAME(@t) + N' ' + @d + N';';
        EXEC (@sql);
    END;
    FETCH NEXT FROM c INTO @t, @n, @d;
END;
CLOSE c; DEALLOCATE c;
GO

/* 2) Geçmiş temizliği */
CREATE OR ALTER PROCEDURE dbo.sp_PurgeHistory
    @LoginDays INT = 90, @JobDays INT = 365, @HuntDays INT = 365, @MaintenanceDays INT = 180
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @run INT, @c INT, @n INT = 0, @now DATETIME2(0) = SYSUTCDATETIME(), @detail NVARCHAR(400) = N'';
    INSERT INTO dbo.MaintenanceRun (Task) VALUES ('purge-history');
    SET @run = SCOPE_IDENTITY();
    BEGIN TRY
        DELETE FROM dbo.LoginAttempt WHERE AttemptedAt < DATEADD(DAY, -@LoginDays, @now);
        SET @c = @@ROWCOUNT; SET @n += @c; SET @detail += CONCAT(N'giriş denemesi ', @c, N'; ');
        DELETE FROM dbo.UserSession WHERE ExpiresAt < @now;
        SET @c = @@ROWCOUNT; SET @n += @c; SET @detail += CONCAT(N'oturum ', @c, N'; ');
        DELETE FROM dbo.ImportJob WHERE StartedAt < DATEADD(DAY, -@JobDays, @now) AND Status <> 'running';   -- hata satırları CASCADE
        SET @c = @@ROWCOUNT; SET @n += @c; SET @detail += CONCAT(N'içe aktarma işi ', @c, N'; ');
        DELETE FROM dbo.HuntRun WHERE StartedAt < DATEADD(DAY, -@HuntDays, @now);   -- eşleşmeler CASCADE, görülmelerde HuntID = NULL
        SET @c = @@ROWCOUNT; SET @n += @c; SET @detail += CONCAT(N'log avı ', @c, N'; ');
        DELETE FROM dbo.MaintenanceRun WHERE StartedAt < DATEADD(DAY, -@MaintenanceDays, @now) AND RunID <> @run;
        SET @c = @@ROWCOUNT; SET @n += @c; SET @detail += CONCAT(N'bakım kaydı ', @c);
        UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), RowsAffected = @n, Status = 'success', Message = @detail WHERE RunID = @run;
    END TRY
    BEGIN CATCH
        UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), Status = 'failed', Message = LEFT(ERROR_MESSAGE(), 400) WHERE RunID = @run;
        THROW;
    END CATCH;
    SELECT @n AS RowsDeleted, @detail AS Detail;
END;
GO

/* 3) Satır sürümlemeli READ COMMITTED (yalnızca kapalıysa; açık oturumların işlemleri geri alınır) */
IF (SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name = DB_NAME()) = 0
    ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;
GO

/* 4) Agent işi: her pazar 03:30 geçmiş temizliği */
USE msdb;
GO
IF SERVERPROPERTY('EngineEdition') <> 4
BEGIN
    DECLARE @name SYSNAME = N'ThreatLens - Geçmiş temizliği', @jobId UNIQUEIDENTIFIER;
    IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = @name)
        EXEC msdb.dbo.sp_delete_job @job_name = @name, @delete_unused_schedule = 1;
    EXEC msdb.dbo.sp_add_job @job_name = @name, @enabled = 1, @job_id = @jobId OUTPUT,
         @description = N'Her pazar 03:30: eski giriş denemeleri, oturumlar, içe aktarma işleri, log avları ve bakım kayıtları. AuditLog korunur.';
    EXEC msdb.dbo.sp_add_jobstep @job_id = @jobId, @step_name = N'Çalıştır', @subsystem = N'TSQL',
         @database_name = N'ThreatLens', @command = N'EXEC dbo.sp_PurgeHistory;', @retry_attempts = 1, @retry_interval = 10;
    EXEC msdb.dbo.sp_add_jobschedule @job_id = @jobId, @name = @name, @enabled = 1, @freq_type = 8, @freq_interval = 1,
         @freq_recurrence_factor = 1, @active_start_time = 33000;
    EXEC msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)';
END;
GO
USE ThreatLens;
GO
