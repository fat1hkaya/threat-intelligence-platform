/* =====================================================================
   ThreatLens - 10: IOC yaşam döngüsü (geçerlilik süresi politikası)
   Tekrar çalıştırılabilir: nesne varsa dokunmaz (IF OBJECT_ID ... IS NULL).
   ---------------------------------------------------------------------
   Bir IOC'nin ne kadar süre "aktif" sayılacağı kaynağına ve tipine göre değişir:
   botnet C2 IP'leri günler içinde el değiştirir, bir zararlı dosyanın özeti ise yıllarca anlamlıdır.
   Politika, öncelik sırasıyla: (kaynak + tip) > (yalnızca kaynak) > (yalnızca tip) > (genel varsayılan).
   ExpiresAt = LastSeen + süre. Yeniden görülen (besleme veya kurum içi görülme) IOC'nin süresi uzar;
   süresi dolanları dbo.sp_ExpireIndicators her gece SQL Server Agent ile pasife alır.
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'dbo.RetentionPolicy') IS NULL
BEGIN
    CREATE TABLE dbo.RetentionPolicy (
        PolicyID     SMALLINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_RetentionPolicy PRIMARY KEY,
        SourceID     SMALLINT NULL CONSTRAINT FK_RetentionPolicy_Source REFERENCES dbo.Source(SourceID) ON DELETE CASCADE,
        TypeID       TINYINT  NULL CONSTRAINT FK_RetentionPolicy_IndicatorType REFERENCES dbo.IndicatorType(TypeID),
        LifetimeDays SMALLINT NOT NULL,
        Note         NVARCHAR(200) NULL,
        CONSTRAINT UQ_RetentionPolicy_Source_Type UNIQUE (SourceID, TypeID),
        CONSTRAINT CK_RetentionPolicy_Days CHECK (LifetimeDays BETWEEN 1 AND 3650)
    );
END;
GO

/* Bakım işlerinin (SQL Server Agent) sonuç günlüğü. Agent geçmişi msdb'dedir; uygulama rolleri msdb'ye
   erişemediği için iş adımı kendi sonucunu buraya da yazar. */
IF OBJECT_ID(N'dbo.MaintenanceRun') IS NULL
BEGIN
    CREATE TABLE dbo.MaintenanceRun (
        RunID        INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_MaintenanceRun PRIMARY KEY,
        Task         VARCHAR(30)   NOT NULL,
        StartedAt    DATETIME2(0)  NOT NULL CONSTRAINT DF_MaintenanceRun_StartedAt DEFAULT (SYSUTCDATETIME()),
        FinishedAt   DATETIME2(0)  NULL,
        RowsAffected INT           NULL,
        Status       VARCHAR(10)   NOT NULL CONSTRAINT DF_MaintenanceRun_Status DEFAULT ('running'),
        Message      NVARCHAR(400) NULL,
        CONSTRAINT CK_MaintenanceRun_Status CHECK (Status IN ('running', 'success', 'failed'))
    );
    CREATE INDEX IX_MaintenanceRun_Task ON dbo.MaintenanceRun (Task, StartedAt DESC);
END;
GO

/* Varsayılan politikalar (yalnızca tablo boşsa) */
IF NOT EXISTS (SELECT 1 FROM dbo.RetentionPolicy)
BEGIN
    INSERT INTO dbo.RetentionPolicy (SourceID, TypeID, LifetimeDays, Note)
    SELECT NULL, NULL, 90, N'Genel varsayılan'
    UNION ALL SELECT NULL, t.TypeID, v.Days, v.Note
    FROM (VALUES ('ipv4', 30, N'IP adresleri hızla el değiştirir'), ('ipv6', 30, N'IP adresleri hızla el değiştirir'),
                 ('domain', 60, N'Alan adları haftalarca kullanılabilir'), ('url', 30, N'Zararlı URL''ler kısa ömürlüdür'),
                 ('md5', 365, N'Dosya özeti değişmez'), ('sha1', 365, N'Dosya özeti değişmez'), ('sha256', 365, N'Dosya özeti değişmez'),
                 ('email', 90, NULL)) AS v(Code, Days, Note)
    JOIN dbo.IndicatorType AS t ON t.Code = v.Code
    UNION ALL SELECT s.SourceID, t.TypeID, 14, N'URLhaus dağıtım URL''leri genelde birkaç günde kapanır'
    FROM dbo.Source AS s CROSS JOIN dbo.IndicatorType AS t WHERE s.Name = N'abuse.ch URLhaus' AND t.Code = 'url'
    UNION ALL SELECT s.SourceID, NULL, 180, N'Analistin elle girdiği kayıtlar daha uzun tutulur'
    FROM dbo.Source AS s WHERE s.Name = N'Analist girişi';
END;
GO

/* Satır içi tablo değerli fonksiyon: bir kaynak+tip için geçerli süre (en özel politika kazanır).
   Satır içi (inline) olduğu için sorgu planına gömülür; satır başına fonksiyon çağrısı maliyeti yoktur. */
CREATE OR ALTER FUNCTION dbo.fn_LifetimeDays (@SourceID SMALLINT, @TypeID TINYINT)
RETURNS TABLE
AS
RETURN
    SELECT TOP (1) p.LifetimeDays, p.PolicyID
    FROM dbo.RetentionPolicy AS p
    WHERE (p.SourceID = @SourceID OR p.SourceID IS NULL)
      AND (p.TypeID = @TypeID OR p.TypeID IS NULL)
    ORDER BY CASE WHEN p.SourceID IS NULL THEN 1 ELSE 0 END, CASE WHEN p.TypeID IS NULL THEN 1 ELSE 0 END;
GO

/* Süresi dolanları pasife çeker. Toplu bakım işlemi olduğundan satır başına denetim kaydı üretmez;
   özet MaintenanceRun tablosuna yazılır. */
CREATE OR ALTER PROCEDURE dbo.sp_ExpireIndicators
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @run INT, @n INT;
    INSERT INTO dbo.MaintenanceRun (Task) VALUES ('expire-indicators');
    SET @run = SCOPE_IDENTITY();
    BEGIN TRY
        EXEC sys.sp_set_session_context @key = N'skip_audit', @value = 1;
        UPDATE dbo.Indicator
        SET Status = 'expired', UpdatedAt = SYSUTCDATETIME()
        WHERE Status = 'active' AND ExpiresAt IS NOT NULL AND ExpiresAt < SYSUTCDATETIME();   -- filtreli indeks: IX_Indicator_ExpiresAt_Active
        SET @n = @@ROWCOUNT;
        EXEC sys.sp_set_session_context @key = N'skip_audit', @value = NULL;
        UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), RowsAffected = @n, Status = 'success',
               Message = CONCAT(@n, N' IOC pasife alındı') WHERE RunID = @run;
    END TRY
    BEGIN CATCH
        EXEC sys.sp_set_session_context @key = N'skip_audit', @value = NULL;
        UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), Status = 'failed', Message = LEFT(ERROR_MESSAGE(), 400) WHERE RunID = @run;
        THROW;
    END CATCH;
    SELECT @n AS ExpiredCount;
END;
GO

/* Haftalık graf bakımı: türetilmiş aktör-aktör kenarlarını yeniler ve iki modeli karşılaştırır */
CREATE OR ALTER PROCEDURE dbo.sp_GraphMaintenance
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @run INT, @bad INT;
    INSERT INTO dbo.MaintenanceRun (Task) VALUES ('graph-maintenance');
    SET @run = SCOPE_IDENTITY();
    EXEC dbo.sp_RefreshActorSimilarity;
    DECLARE @c TABLE (ObjectName SYSNAME, Kind VARCHAR(5), Relational INT, Graph INT, IsConsistent BIT);
    INSERT INTO @c EXEC dbo.sp_CheckGraphConsistency;
    SET @bad = (SELECT COUNT(*) FROM @c WHERE IsConsistent = 0);
    IF @bad > 0 EXEC dbo.sp_SyncGraph;      -- tutarsızlık varsa grafı ilişkisel modelden yeniden kur
    UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), RowsAffected = @bad, Status = 'success',
           Message = CASE WHEN @bad = 0 THEN N'Graf tutarlı' ELSE CONCAT(@bad, N' tutarsız nesne onarıldı (sp_SyncGraph)') END
    WHERE RunID = @run;
END;
GO

/* Süresi tanımsız IOC'lere politikaya göre bitiş tarihi ver (ilk kurulum / eski kayıtlar) */
EXEC sys.sp_set_session_context @key = N'skip_audit', @value = 1;
UPDATE i SET i.ExpiresAt = DATEADD(DAY, lp.LifetimeDays, i.LastSeen)
FROM dbo.Indicator AS i
CROSS APPLY dbo.fn_LifetimeDays(i.SourceID, i.TypeID) AS lp
WHERE i.ExpiresAt IS NULL;
EXEC sys.sp_set_session_context @key = N'skip_audit', @value = NULL;
GO

/* Yetkiler: politika herkesçe okunur, yalnızca yönetici değiştirir */
GRANT SELECT ON dbo.RetentionPolicy TO tip_reader;
GRANT SELECT ON dbo.MaintenanceRun TO tip_reader;
GRANT INSERT, UPDATE, DELETE ON dbo.RetentionPolicy TO tip_admin;
GO
