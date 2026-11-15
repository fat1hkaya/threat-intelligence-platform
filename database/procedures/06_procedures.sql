/* =====================================================================
   ThreatLens - 06: Saklı yordamlar
   Hata kodları: 50001-50099 iş kuralı ihlalleri (mesajı arayüzde gösterilir)
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---------------------------------------------------------------------
   sp_SaveIndicator: arayüzden tek gösterge ekler veya günceller.
   - Değerin normalleştirilmesi uygulama katmanında yapılır (app/services/normalize.py);
     veritabanı biçimi fn_IsValidIndicator ile bir kez daha doğrular.
   - İyimser eşzamanlılık: güncellemede istemcinin okuduğu RowVer gönderilir. Kayıt bu
     arada başkası tarafından değiştirildiyse RowVer tutmaz ve işlem reddedilir.
   - Etiketler dahil tüm adımlar tek transaction: ya hepsi ya hiçbiri.
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.sp_SaveIndicator
    @IndicatorID     BIGINT = NULL,          -- NULL ise yeni kayıt
    @TypeCode        VARCHAR(10),
    @Value           NVARCHAR(400),
    @NormalizedValue NVARCHAR(400),
    @Confidence      TINYINT,
    @SeverityCode    VARCHAR(10),
    @TLPCode         VARCHAR(12),
    @SourceID        SMALLINT,
    @Status          VARCHAR(15) = 'active',
    @Description     NVARCHAR(1000) = NULL,
    @ExpiresAt       DATETIME2(0) = NULL,
    @TagsJson        NVARCHAR(MAX) = NULL,   -- ["c2","botnet"]
    @RowVer          VARCHAR(18) = NULL,     -- '0x00000000000007D1' (güncellemede)
    @UserID          INT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @TypeID TINYINT     = (SELECT TypeID FROM dbo.IndicatorType WHERE Code = @TypeCode);
    DECLARE @SeverityID TINYINT = (SELECT SeverityID FROM dbo.SeverityLevel WHERE Code = @SeverityCode);
    DECLARE @TLPID TINYINT      = (SELECT TLPID FROM dbo.TLPLevel WHERE Code = @TLPCode);

    IF @TypeID IS NULL     THROW 50001, N'Geçersiz gösterge tipi.', 1;
    IF @SeverityID IS NULL THROW 50002, N'Geçersiz önem düzeyi.', 1;
    IF @TLPID IS NULL      THROW 50003, N'Geçersiz TLP düzeyi.', 1;
    IF NOT EXISTS (SELECT 1 FROM dbo.Source WHERE SourceID = @SourceID)
        THROW 50004, N'Kaynak bulunamadı.', 1;
    IF dbo.fn_IsValidIndicator(@TypeCode, @NormalizedValue) = 0
        THROW 50005, N'Değer, seçilen gösterge tipinin biçimine uymuyor.', 1;
    IF EXISTS (SELECT 1 FROM dbo.Indicator
               WHERE TypeID = @TypeID AND NormalizedValue = @NormalizedValue
                 AND (@IndicatorID IS NULL OR IndicatorID <> @IndicatorID))
        THROW 50006, N'Bu gösterge zaten kayıtlı.', 1;

    BEGIN TRY
        BEGIN TRANSACTION;

        IF @IndicatorID IS NULL
        BEGIN
            INSERT INTO dbo.Indicator (TypeID, Value, NormalizedValue, Confidence, SeverityID, TLPID, SourceID, Status, Description, ExpiresAt, CreatedBy)
            VALUES (@TypeID, @Value, @NormalizedValue, @Confidence, @SeverityID, @TLPID, @SourceID, @Status, @Description, @ExpiresAt, @UserID);
            SET @IndicatorID = SCOPE_IDENTITY();
        END
        ELSE
        BEGIN
            UPDATE dbo.Indicator
            SET TypeID = @TypeID, Value = @Value, NormalizedValue = @NormalizedValue, Confidence = @Confidence,
                SeverityID = @SeverityID, TLPID = @TLPID, SourceID = @SourceID, Status = @Status,
                Description = @Description, ExpiresAt = @ExpiresAt, UpdatedAt = SYSUTCDATETIME()
            WHERE IndicatorID = @IndicatorID
              AND (@RowVer IS NULL OR RowVer = CONVERT(BINARY(8), @RowVer, 1));

            IF @@ROWCOUNT = 0
            BEGIN
                IF EXISTS (SELECT 1 FROM dbo.Indicator WHERE IndicatorID = @IndicatorID)
                    THROW 50009, N'Bu kayıt siz düzenlerken başka bir kullanıcı tarafından değiştirildi. Sayfayı yenileyip tekrar deneyin.', 1;
                THROW 50007, N'Gösterge bulunamadı.', 1;
            END;
        END;

        IF @TagsJson IS NOT NULL
        BEGIN
            DECLARE @tags TABLE (Name NVARCHAR(50) PRIMARY KEY);
            INSERT INTO @tags (Name)
            SELECT DISTINCT LOWER(LTRIM(RTRIM(LEFT([value], 50))))
            FROM OPENJSON(@TagsJson)
            WHERE LEN(LTRIM(RTRIM([value]))) > 0;

            INSERT INTO dbo.Tag (Name)
            SELECT t.Name FROM @tags AS t
            WHERE NOT EXISTS (SELECT 1 FROM dbo.Tag AS x WHERE x.Name = t.Name);

            DELETE it
            FROM dbo.IndicatorTag AS it
            JOIN dbo.Tag AS tg ON tg.TagID = it.TagID
            WHERE it.IndicatorID = @IndicatorID
              AND NOT EXISTS (SELECT 1 FROM @tags AS t WHERE t.Name = tg.Name);

            INSERT INTO dbo.IndicatorTag (IndicatorID, TagID)
            SELECT @IndicatorID, tg.TagID
            FROM @tags AS t
            JOIN dbo.Tag AS tg ON tg.Name = t.Name
            WHERE NOT EXISTS (SELECT 1 FROM dbo.IndicatorTag AS x
                              WHERE x.IndicatorID = @IndicatorID AND x.TagID = tg.TagID);
        END;

        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH;

    SELECT @IndicatorID AS IndicatorID;
END;
GO

/* ---------------------------------------------------------------------
   sp_BulkImportIndicators: bir kaynaktan gelen gösterge yığınını JSON olarak alır,
   küme tabanlı (set-based) işler. Python içe aktarıcıları satırları önceden normalleştirir;
   normalleştirilemeyen satırlar "error" alanıyla gelir.
   JSON öğesi: { "row","type","value","normalized","error","confidence","severity","tlp",
                 "description","first_seen","last_seen","expires_at",
                 "malware","role","evidence","tags":[...] }
   @Strict = 0: geçerli satırlar yüklenir, hatalılar ImportJobError'a yazılır (durum: partial).
   @Strict = 1: tek bir hatalı satır bile varsa TÜM yığın ROLLBACK ile geri alınır (durum: failed).
                Hata kayıtları geri almadan SONRA yazılır; tablo değişkeni (@stage) ROLLBACK'ten
                etkilenmediği için reddedilen satırlar hâlâ elimizdedir.
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.sp_BulkImportIndicators
    @SourceID SMALLINT,
    @Json     NVARCHAR(MAX),
    @JobID    INT = NULL,
    @Strict   BIT = 0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT OFF;      -- THROW'u kendimiz yakalayıp hata kaydı yazacağız

    IF NOT EXISTS (SELECT 1 FROM dbo.Source WHERE SourceID = @SourceID)
        THROW 50004, N'Kaynak bulunamadı.', 1;

    DECLARE @stage TABLE (
        RowNo           INT NOT NULL PRIMARY KEY,
        TypeID          TINYINT NULL,
        TypeCode        VARCHAR(10) NULL,
        Value           NVARCHAR(400) NULL,
        NormalizedValue NVARCHAR(400) NULL,
        Error           NVARCHAR(300) NULL,
        Confidence      TINYINT NOT NULL,
        SeverityID      TINYINT NOT NULL,
        TLPID           TINYINT NOT NULL,
        Description     NVARCHAR(1000) NULL,
        FirstSeen       DATETIME2(0) NOT NULL,
        LastSeen        DATETIME2(0) NOT NULL,
        ExpiresAt       DATETIME2(0) NULL,
        Malware         NVARCHAR(100) NULL,
        Role            VARCHAR(12) NULL,
        EvidenceText    NVARCHAR(1000) NULL,
        TagsJson        NVARCHAR(MAX) NULL,
        IndicatorID     BIGINT NULL,
        IsDuplicate     BIT NOT NULL DEFAULT (0)
    );

    DECLARE @now DATETIME2(0) = SYSUTCDATETIME();
    DECLARE @defSeverity TINYINT = (SELECT SeverityID FROM dbo.SeverityLevel WHERE Code = 'medium');
    DECLARE @defTLP TINYINT      = (SELECT TLPID FROM dbo.TLPLevel WHERE Code = 'TLP:CLEAR');

    INSERT INTO @stage (RowNo, TypeID, TypeCode, Value, NormalizedValue, Error, Confidence, SeverityID, TLPID, Description,
                        FirstSeen, LastSeen, ExpiresAt, Malware, Role, EvidenceText, TagsJson)
    SELECT ISNULL(j.[row], CAST(k.[key] AS INT) + 1), it.TypeID, j.[type], LEFT(j.[value], 400), LEFT(j.normalized, 400), j.error,
           CASE WHEN j.confidence BETWEEN 0 AND 100 THEN j.confidence ELSE 50 END,
           ISNULL(sv.SeverityID, @defSeverity), ISNULL(tl.TLPID, @defTLP), j.[description],
           ISNULL(j.first_seen, @now),
           CASE WHEN ISNULL(j.last_seen, @now) < ISNULL(j.first_seen, @now) THEN ISNULL(j.first_seen, @now) ELSE ISNULL(j.last_seen, @now) END,
           j.expires_at, NULLIF(LTRIM(RTRIM(j.malware)), N''),
           CASE WHEN j.[role] IN ('c2','payload','dropper','exfil','phishing') THEN j.[role] ELSE 'other' END,
           j.evidence, j.tags
    FROM OPENJSON(@Json) AS k
    CROSS APPLY OPENJSON(k.[value]) WITH (
        [row]         INT            '$.row',
        [type]        VARCHAR(10)    '$.type',
        [value]       NVARCHAR(1000) '$.value',
        normalized    NVARCHAR(1000) '$.normalized',
        error         NVARCHAR(300)  '$.error',
        confidence    INT            '$.confidence',
        severity      VARCHAR(10)    '$.severity',
        tlp           VARCHAR(12)    '$.tlp',
        [description] NVARCHAR(1000) '$.description',
        first_seen    DATETIME2(0)   '$.first_seen',
        last_seen     DATETIME2(0)   '$.last_seen',
        expires_at    DATETIME2(0)   '$.expires_at',
        malware       NVARCHAR(100)  '$.malware',
        [role]        VARCHAR(12)    '$.role',
        evidence      NVARCHAR(1000) '$.evidence',
        tags          NVARCHAR(MAX)  '$.tags' AS JSON
    ) AS j
    LEFT JOIN dbo.IndicatorType AS it ON it.Code = j.[type]
    LEFT JOIN dbo.SeverityLevel AS sv ON sv.Code = j.severity
    LEFT JOIN dbo.TLPLevel      AS tl ON tl.Code = j.tlp;

    -- Veritabanı tarafı doğrulama: tip, boş değer, biçim
    UPDATE @stage SET Error = N'Bilinmeyen gösterge tipi: ' + ISNULL(TypeCode, N'(boş)') WHERE Error IS NULL AND TypeID IS NULL;
    UPDATE @stage SET Error = N'Değer boş.' WHERE Error IS NULL AND (NormalizedValue IS NULL OR LEN(NormalizedValue) = 0);
    UPDATE @stage SET Error = N'Değer ' + TypeCode + N' biçimine uymuyor.'
    WHERE Error IS NULL AND dbo.fn_IsValidIndicator(TypeCode, NormalizedValue) = 0;

    -- Aynı yığındaki tekrarlar: en yeni LastSeen kalır, diğerleri "atlandı" sayılır (pencere fonksiyonu)
    ;WITH d AS (
        SELECT RowNo, ROW_NUMBER() OVER (PARTITION BY TypeID, NormalizedValue ORDER BY LastSeen DESC, RowNo) AS rn
        FROM @stage WHERE Error IS NULL
    )
    UPDATE s SET s.IsDuplicate = 1 FROM @stage AS s JOIN d ON d.RowNo = s.RowNo WHERE d.rn > 1;

    DECLARE @read INT     = (SELECT COUNT(*) FROM @stage);
    DECLARE @failed INT   = (SELECT COUNT(*) FROM @stage WHERE Error IS NOT NULL);
    DECLARE @skipped INT  = (SELECT COUNT(*) FROM @stage WHERE IsDuplicate = 1);
    DECLARE @inserted INT = 0, @updated INT = 0, @rolledBack INT = 0, @status VARCHAR(10), @message NVARCHAR(1000) = NULL;
    DECLARE @evidenceSource SMALLINT = @SourceID;

    BEGIN TRY
        -- Toplu içe aktarma satır başına denetim kaydı üretmesin; özet ImportJob'da tutulur
        EXEC sys.sp_set_session_context @key = N'skip_audit', @value = 1;
        BEGIN TRANSACTION;

        -- 1) Var olanları güncelle (son görülme ileri, güven yukarı; iptal edilmiş/yanlış pozitif dokunulmaz)
        UPDATE i
        SET i.LastSeen   = CASE WHEN s.LastSeen > i.LastSeen THEN s.LastSeen ELSE i.LastSeen END,
            i.Confidence = CASE WHEN s.Confidence > i.Confidence THEN s.Confidence ELSE i.Confidence END,
            i.Status     = CASE WHEN i.Status = 'expired' THEN 'active' ELSE i.Status END,
            i.UpdatedAt  = @now
        FROM dbo.Indicator AS i
        JOIN @stage AS s ON s.TypeID = i.TypeID AND s.NormalizedValue = i.NormalizedValue
        WHERE s.Error IS NULL AND s.IsDuplicate = 0;
        SET @updated = @@ROWCOUNT;

        -- 2) Yenileri ekle
        INSERT INTO dbo.Indicator (TypeID, Value, NormalizedValue, Confidence, SeverityID, TLPID, SourceID, Description, FirstSeen, LastSeen, ExpiresAt)
        SELECT s.TypeID, ISNULL(s.Value, s.NormalizedValue), s.NormalizedValue, s.Confidence, s.SeverityID, s.TLPID, @SourceID,
               s.Description, s.FirstSeen, s.LastSeen, s.ExpiresAt
        FROM @stage AS s
        WHERE s.Error IS NULL AND s.IsDuplicate = 0
          AND NOT EXISTS (SELECT 1 FROM dbo.Indicator AS i WHERE i.TypeID = s.TypeID AND i.NormalizedValue = s.NormalizedValue);
        SET @inserted = @@ROWCOUNT;

        -- Katı mod: hatalı satır varsa buraya kadar yapılan HER ŞEY geri alınır
        IF @Strict = 1 AND @failed > 0
        BEGIN
            SET @rolledBack = @inserted + @updated;
            THROW 50030, N'Katı modda hatalı satır bulundu; tüm yığın geri alındı.', 1;
        END;

        UPDATE s SET s.IndicatorID = i.IndicatorID
        FROM @stage AS s
        JOIN dbo.Indicator AS i ON i.TypeID = s.TypeID AND i.NormalizedValue = s.NormalizedValue
        WHERE s.Error IS NULL AND s.IsDuplicate = 0;

        -- 3) Zararlı yazılım bağlantısı. Aile adı bilinmiyorsa "genel" tipte açılır.
        --    Kanıt: kaynağın bu göstergeyi bu aileyle ilişkilendirdiği beyan (ör. ThreatFox "malware_printable")
        INSERT INTO dbo.Malware (Name, MalwareTypeID)
        SELECT DISTINCT s.Malware, (SELECT MalwareTypeID FROM dbo.MalwareType WHERE Code = 'malware')
        FROM @stage AS s
        WHERE s.IndicatorID IS NOT NULL AND s.Malware IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM dbo.Malware AS m WHERE m.Name = s.Malware)
          AND NOT EXISTS (SELECT 1 FROM dbo.MalwareAlias AS ma WHERE ma.Alias = s.Malware);

        DECLARE @links TABLE (IndicatorID BIGINT, MalwareID INT, Role VARCHAR(12), Confidence TINYINT, EvidenceText NVARCHAR(1000), EvidenceID INT NULL,
                              PRIMARY KEY (IndicatorID, MalwareID));
        INSERT INTO @links (IndicatorID, MalwareID, Role, Confidence, EvidenceText)
        SELECT s.IndicatorID, MIN(x.MalwareID), MIN(s.Role), MAX(s.Confidence),
               MIN(ISNULL(s.EvidenceText, N'Kaynak bu göstergeyi ' + s.Malware + N' ailesiyle ilişkilendiriyor.'))
        FROM @stage AS s
        CROSS APPLY (
            SELECT TOP (1) q.MalwareID
            FROM (SELECT m.MalwareID, 1 AS Pri FROM dbo.Malware AS m WHERE m.Name = s.Malware
                  UNION ALL
                  SELECT ma.MalwareID, 2 FROM dbo.MalwareAlias AS ma WHERE ma.Alias = s.Malware) AS q
            ORDER BY q.Pri, q.MalwareID
        ) AS x
        WHERE s.IndicatorID IS NOT NULL AND s.Malware IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM dbo.MalwareIndicator AS mi WHERE mi.MalwareID = x.MalwareID AND mi.IndicatorID = s.IndicatorID)
        GROUP BY s.IndicatorID, x.MalwareID;

        -- Her bağlantı için bir kanıt satırı (MERGE ... OUTPUT ile yeni kimlikler eşlenir)
        DECLARE @evMap TABLE (EvidenceID INT, IndicatorID BIGINT, MalwareID INT);
        MERGE dbo.Evidence AS t
        USING @links AS l ON 1 = 0
        WHEN NOT MATCHED THEN INSERT (SourceID, Summary) VALUES (@evidenceSource, l.EvidenceText)
        OUTPUT inserted.EvidenceID, l.IndicatorID, l.MalwareID INTO @evMap;

        INSERT INTO dbo.MalwareIndicator (MalwareID, IndicatorID, Role, Confidence, EvidenceID)
        SELECT l.MalwareID, l.IndicatorID, l.Role, l.Confidence, e.EvidenceID
        FROM @links AS l JOIN @evMap AS e ON e.IndicatorID = l.IndicatorID AND e.MalwareID = l.MalwareID;

        -- 4) Etiketler
        DECLARE @tags TABLE (IndicatorID BIGINT NOT NULL, Name NVARCHAR(50) NOT NULL, PRIMARY KEY (IndicatorID, Name));
        INSERT INTO @tags (IndicatorID, Name)
        SELECT DISTINCT s.IndicatorID, LOWER(LTRIM(RTRIM(LEFT(t.[value], 50))))
        FROM @stage AS s
        CROSS APPLY OPENJSON(s.TagsJson) AS t
        WHERE s.IndicatorID IS NOT NULL AND s.TagsJson IS NOT NULL AND LEN(LTRIM(RTRIM(t.[value]))) > 0;

        INSERT INTO dbo.Tag (Name)
        SELECT DISTINCT t.Name FROM @tags AS t
        WHERE NOT EXISTS (SELECT 1 FROM dbo.Tag AS x WHERE x.Name = t.Name);

        INSERT INTO dbo.IndicatorTag (IndicatorID, TagID)
        SELECT t.IndicatorID, tg.TagID
        FROM @tags AS t
        JOIN dbo.Tag AS tg ON tg.Name = t.Name
        WHERE NOT EXISTS (SELECT 1 FROM dbo.IndicatorTag AS x WHERE x.IndicatorID = t.IndicatorID AND x.TagID = tg.TagID);

        COMMIT TRANSACTION;
        SET @status = CASE WHEN @failed = 0 THEN 'success' WHEN @inserted + @updated > 0 THEN 'partial' ELSE 'failed' END;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        SET @status = 'failed';
        SET @message = ERROR_MESSAGE();
        IF ERROR_NUMBER() <> 50030 SET @rolledBack = @inserted + @updated;
        SET @inserted = 0; SET @updated = 0;
    END CATCH;
    EXEC sys.sp_set_session_context @key = N'skip_audit', @value = NULL;

    -- Hata kayıtları, geri almadan sonra yazılır (kalıcı olsun diye)
    IF @JobID IS NOT NULL
    BEGIN
        INSERT INTO dbo.ImportJobError (JobID, RowNo, RawValue, Reason)
        SELECT @JobID, s.RowNo, LEFT(ISNULL(s.Value, s.NormalizedValue), 400), s.Error
        FROM @stage AS s WHERE s.Error IS NOT NULL;

        IF @message IS NOT NULL AND @failed = 0
            INSERT INTO dbo.ImportJobError (JobID, RowNo, RawValue, Reason) VALUES (@JobID, 0, NULL, LEFT(@message, 300));

        UPDATE dbo.ImportJob
        SET RowsRead = RowsRead + @read, RowsInserted = RowsInserted + @inserted, RowsUpdated = RowsUpdated + @updated,
            RowsSkipped = RowsSkipped + @skipped, RowsFailed = RowsFailed + @failed,
            ErrorMessage = COALESCE(@message, ErrorMessage)
        WHERE JobID = @JobID;
    END;

    SELECT @read AS RowsRead, @inserted AS RowsInserted, @updated AS RowsUpdated, @skipped AS RowsSkipped,
           @failed AS RowsFailed, @rolledBack AS RowsRolledBack, @status AS Status, @message AS Message;
END;
GO

CREATE OR ALTER PROCEDURE dbo.sp_StartImportJob
    @SourceID SMALLINT, @JobType VARCHAR(10) = 'feed', @FileName NVARCHAR(200) = NULL, @IsStrict BIT = 0, @UserID INT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.ImportJob (SourceID, JobType, FileName, IsStrict, StartedBy) VALUES (@SourceID, @JobType, @FileName, @IsStrict, @UserID);
    SELECT CAST(SCOPE_IDENTITY() AS INT) AS JobID;
END;
GO

/* İşi kapatır. @Status verilmezse sayılara göre belirlenir. */
CREATE OR ALTER PROCEDURE dbo.sp_FinishImportJob @JobID INT, @Status VARCHAR(10) = NULL, @ErrorMessage NVARCHAR(1000) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE dbo.ImportJob
    SET FinishedAt = SYSUTCDATETIME(),
        ErrorMessage = COALESCE(@ErrorMessage, ErrorMessage),
        Status = COALESCE(@Status,
                          CASE WHEN IsStrict = 1 AND RowsFailed > 0 THEN 'failed'
                               WHEN RowsFailed = 0 AND ErrorMessage IS NULL THEN 'success'
                               WHEN RowsInserted + RowsUpdated > 0 THEN 'partial'
                               ELSE 'failed' END)
    WHERE JobID = @JobID;
    SELECT JobID, Status, RowsRead, RowsInserted, RowsUpdated, RowsSkipped, RowsFailed, ErrorMessage FROM dbo.ImportJob WHERE JobID = @JobID;
END;
GO

/* Görülme kaydı ekler. LastSeen güncellemesi trg_Sighting_AfterInsert tetikleyicisindedir. */
CREATE OR ALTER PROCEDURE dbo.sp_AddSighting
    @IndicatorID BIGINT,
    @Quantity    INT = 1,
    @Location    NVARCHAR(100) = NULL,
    @Note        NVARCHAR(400) = NULL,
    @SightedAt   DATETIME2(0) = NULL,
    @UserID      INT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM dbo.Indicator WHERE IndicatorID = @IndicatorID)
        THROW 50007, N'Gösterge bulunamadı.', 1;
    IF @SightedAt > DATEADD(MINUTE, 5, SYSUTCDATETIME())
        THROW 50008, N'Görülme zamanı gelecekte olamaz.', 1;

    INSERT INTO dbo.Sighting (IndicatorID, SightedAt, Quantity, Location, Note, ReportedBy)
    VALUES (@IndicatorID, ISNULL(@SightedAt, SYSUTCDATETIME()), @Quantity, @Location, @Note, @UserID);

    SELECT CAST(SCOPE_IDENTITY() AS BIGINT) AS SightingID;
END;
GO

/* Süresi dolan göstergeleri pasife çeker (zamanlanmış görev olarak çalıştırılabilir) */
CREATE OR ALTER PROCEDURE dbo.sp_ExpireIndicators
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE dbo.Indicator
    SET Status = 'expired', UpdatedAt = SYSUTCDATETIME()
    WHERE Status = 'active' AND ExpiresAt IS NOT NULL AND ExpiresAt < SYSUTCDATETIME();
    SELECT @@ROWCOUNT AS ExpiredCount;
END;
GO

/* ---------------------------------------------------------------------
   sp_GlobalSearch: tek kutudan her şeyi ara (komut paleti).
   Gösterge değeri, aktör/zararlı adı ve takma adı, kampanya,
   ATT&CK kimliği (T1059), CVE numarası.
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.sp_GlobalSearch
    @Query NVARCHAR(200),
    @Top   INT = 6
AS
BEGIN
    SET NOCOUNT ON;
    SET @Query = LTRIM(RTRIM(@Query));
    IF LEN(@Query) < 2 BEGIN SELECT TOP (0) CAST(NULL AS VARCHAR(15)) AS EntityType, CAST(NULL AS BIGINT) AS EntityID, CAST(NULL AS NVARCHAR(400)) AS Title, CAST(NULL AS NVARCHAR(200)) AS Subtitle; RETURN; END;

    -- LIKE joker karakterlerini etkisizleştir
    DECLARE @p NVARCHAR(420) = N'%' + REPLACE(REPLACE(REPLACE(@Query, N'[', N'[[]'), N'%', N'[%]'), N'_', N'[_]') + N'%';

    DECLARE @r TABLE (
        Seq INT IDENTITY(1,1) PRIMARY KEY,
        EntityType VARCHAR(15) NOT NULL, EntityID BIGINT NOT NULL,
        Title NVARCHAR(400) NOT NULL, Subtitle NVARCHAR(200) NULL
    );

    INSERT INTO @r (EntityType, EntityID, Title, Subtitle)
    SELECT TOP (@Top) 'indicator', v.IndicatorID, v.Value,
           v.TypeName + N', risk ' + CAST(v.RiskScore AS NVARCHAR(3))
    FROM dbo.vw_Indicator AS v
    WHERE v.Value LIKE @p
    ORDER BY CASE WHEN v.Value = @Query THEN 0 ELSE 1 END, v.LastSeen DESC;

    INSERT INTO @r (EntityType, EntityID, Title, Subtitle)
    SELECT TOP (@Top) 'actor', a.ActorID, a.Name,
           ISNULL(N'Diğer adı: ' + al.Alias, ISNULL(a.ExternalID, N'Tehdit aktörü'))
    FROM dbo.ThreatActor AS a
    OUTER APPLY (SELECT TOP (1) x.Alias FROM dbo.ActorAlias AS x
                 WHERE x.ActorID = a.ActorID AND x.Alias LIKE @p AND a.Name NOT LIKE @p) AS al
    WHERE a.Name LIKE @p OR a.ExternalID = @Query OR al.Alias IS NOT NULL
    ORDER BY CASE WHEN a.Name LIKE @p THEN 0 ELSE 1 END, a.Name;

    INSERT INTO @r (EntityType, EntityID, Title, Subtitle)
    SELECT TOP (@Top) 'malware', m.MalwareID, m.Name,
           ISNULL(N'Diğer adı: ' + al.Alias, mt.Name)
    FROM dbo.Malware AS m
    JOIN dbo.MalwareType AS mt ON mt.MalwareTypeID = m.MalwareTypeID
    OUTER APPLY (SELECT TOP (1) x.Alias FROM dbo.MalwareAlias AS x
                 WHERE x.MalwareID = m.MalwareID AND x.Alias LIKE @p AND m.Name NOT LIKE @p) AS al
    WHERE m.Name LIKE @p OR m.ExternalID = @Query OR al.Alias IS NOT NULL
    ORDER BY CASE WHEN m.Name LIKE @p THEN 0 ELSE 1 END, m.Name;

    INSERT INTO @r (EntityType, EntityID, Title, Subtitle)
    SELECT TOP (@Top) 'campaign', c.CampaignID, c.Name, ISNULL(c.ExternalID, N'Kampanya')
    FROM dbo.Campaign AS c
    WHERE c.Name LIKE @p OR c.ExternalID = @Query
    ORDER BY c.Name;

    INSERT INTO @r (EntityType, EntityID, Title, Subtitle)
    SELECT TOP (@Top) 'technique', t.TechniqueID, t.Name, t.ExternalID
    FROM dbo.Technique AS t
    WHERE t.Name LIKE @p OR t.ExternalID LIKE @Query + N'%'
    ORDER BY CASE WHEN t.ExternalID = @Query THEN 0 ELSE 1 END, t.ExternalID;

    INSERT INTO @r (EntityType, EntityID, Title, Subtitle)
    SELECT TOP (@Top) 'vulnerability', v.VulnerabilityID, v.CveID, LEFT(v.Title, 200)
    FROM dbo.Vulnerability AS v
    WHERE v.CveID LIKE @p OR v.Title LIKE @p
    ORDER BY v.PublishedDate DESC;

    SELECT EntityType, EntityID, Title, Subtitle FROM @r ORDER BY Seq;
END;
GO

/* ---------------------------------------------------------------------
   sp_GetNeighborhood: bir düğümden başlayıp @Depth adım uzaklığa kadar
   ilişki grafını gezer (genişlik öncelikli arama, döngüye karşı korumalı).
   İki sonuç kümesi döndürür: düğümler ve kenarlar.
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.sp_GetNeighborhood
    @NodeType          VARCHAR(15),
    @NodeID            BIGINT,
    @Depth             TINYINT = 1,
    @IncludeTechniques BIT = 0,
    @IncludeIndicators BIT = 1,
    @MaxNodes          INT = 120
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @nodes TABLE (
        NodeType VARCHAR(15) NOT NULL,
        NodeID   BIGINT      NOT NULL,
        Lvl      TINYINT     NOT NULL,
        PRIMARY KEY (NodeType, NodeID)
    );

    IF NOT EXISTS (SELECT 1 FROM dbo.vw_GraphNode WHERE NodeType = @NodeType AND NodeID = @NodeID)
        THROW 50010, N'Düğüm bulunamadı.', 1;

    INSERT INTO @nodes (NodeType, NodeID, Lvl) VALUES (@NodeType, @NodeID, 0);

    IF @Depth > 3 SET @Depth = 3;
    IF @Depth < 1 SET @Depth = 1;

    DECLARE @lvl TINYINT = 0, @room INT, @added INT;

    WHILE @lvl < @Depth
    BEGIN
        SET @room = @MaxNodes - (SELECT COUNT(*) FROM @nodes);
        IF @room <= 0 BREAK;

        INSERT INTO @nodes (NodeType, NodeID, Lvl)
        SELECT TOP (@room) n.NodeType, n.NodeID, @lvl + 1
        FROM (
            SELECT e.TargetType AS NodeType, e.TargetID AS NodeID
            FROM dbo.vw_GraphEdge AS e
            JOIN @nodes AS f ON f.NodeType = e.SourceType AND f.NodeID = e.SourceID AND f.Lvl = @lvl
            UNION
            SELECT e.SourceType, e.SourceID
            FROM dbo.vw_GraphEdge AS e
            JOIN @nodes AS f ON f.NodeType = e.TargetType AND f.NodeID = e.TargetID AND f.Lvl = @lvl
        ) AS n
        WHERE (@IncludeTechniques = 1 OR n.NodeType <> 'technique')
          AND (@IncludeIndicators = 1 OR n.NodeType <> 'indicator')
          AND NOT EXISTS (SELECT 1 FROM @nodes AS x WHERE x.NodeType = n.NodeType AND x.NodeID = n.NodeID)
        ORDER BY CASE n.NodeType WHEN 'actor' THEN 1 WHEN 'campaign' THEN 2 WHEN 'malware' THEN 3
                                 WHEN 'vulnerability' THEN 4 WHEN 'technique' THEN 5 ELSE 6 END, n.NodeID DESC;

        SET @added = @@ROWCOUNT;
        IF @added = 0 BREAK;
        SET @lvl = @lvl + 1;
    END;

    SELECT n.NodeType, n.NodeID, g.Label, g.SubLabel, n.Lvl
    FROM @nodes AS n
    JOIN dbo.vw_GraphNode AS g ON g.NodeType = n.NodeType AND g.NodeID = n.NodeID
    ORDER BY n.Lvl, n.NodeType, g.Label;

    SELECT e.SourceType, e.SourceID, e.TargetType, e.TargetID, e.Relation, e.Confidence, e.EvidenceID
    FROM dbo.vw_GraphEdge AS e
    JOIN @nodes AS a ON a.NodeType = e.SourceType AND a.NodeID = e.SourceID
    JOIN @nodes AS b ON b.NodeType = e.TargetType AND b.NodeID = e.TargetID;
END;
GO

/* ---------------------------------------------------------------------
   sp_AttackMatrix: ATT&CK matrisi (taktik x teknik) ve kapsama sayıları.
   Alt teknikler üst tekniğe toplanır. İsteğe bağlı olarak bir aktörün,
   zararlının veya kampanyanın kullandığı teknikler işaretlenir.
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.sp_AttackMatrix
    @ActorID    INT = NULL,
    @MalwareID  INT = NULL,
    @CampaignID INT = NULL
AS
BEGIN
    SET NOCOUNT ON;

    ;WITH tech AS (
        SELECT TechniqueID, COALESCE(ParentTechniqueID, TechniqueID) AS RootID FROM dbo.Technique
    ),
    ac AS (
        SELECT x.RootID, COUNT(DISTINCT a.ActorID) AS ActorCount
        FROM dbo.ActorTechnique AS a JOIN tech AS x ON x.TechniqueID = a.TechniqueID
        GROUP BY x.RootID
    ),
    mc AS (
        SELECT x.RootID, COUNT(DISTINCT m.MalwareID) AS MalwareCount
        FROM dbo.MalwareTechnique AS m JOIN tech AS x ON x.TechniqueID = m.TechniqueID
        GROUP BY x.RootID
    ),
    sub AS (
        SELECT ParentTechniqueID AS RootID, COUNT(*) AS SubCount
        FROM dbo.Technique WHERE ParentTechniqueID IS NOT NULL
        GROUP BY ParentTechniqueID
    ),
    hl AS (
        SELECT x.RootID FROM dbo.ActorTechnique AS a JOIN tech AS x ON x.TechniqueID = a.TechniqueID WHERE a.ActorID = @ActorID
        UNION
        SELECT x.RootID FROM dbo.MalwareTechnique AS m JOIN tech AS x ON x.TechniqueID = m.TechniqueID WHERE m.MalwareID = @MalwareID
        UNION
        SELECT x.RootID FROM dbo.CampaignTechnique AS c JOIN tech AS x ON x.TechniqueID = c.TechniqueID WHERE c.CampaignID = @CampaignID
    )
    SELECT ta.TacticID, ta.ExternalID AS TacticExternalID, ta.Name AS TacticName, ta.DisplayOrder,
           t.TechniqueID, t.ExternalID, t.Name,
           ISNULL(ac.ActorCount, 0)   AS ActorCount,
           ISNULL(mc.MalwareCount, 0) AS MalwareCount,
           ISNULL(sub.SubCount, 0)    AS SubTechniqueCount,
           CAST(CASE WHEN hl.RootID IS NOT NULL THEN 1 ELSE 0 END AS BIT) AS Highlighted
    FROM dbo.Tactic AS ta
    JOIN dbo.TechniqueTactic AS tt ON tt.TacticID = ta.TacticID
    JOIN dbo.Technique AS t ON t.TechniqueID = tt.TechniqueID AND t.ParentTechniqueID IS NULL
    LEFT JOIN ac  ON ac.RootID  = t.TechniqueID
    LEFT JOIN mc  ON mc.RootID  = t.TechniqueID
    LEFT JOIN sub ON sub.RootID = t.TechniqueID
    LEFT JOIN hl  ON hl.RootID  = t.TechniqueID
    ORDER BY ta.DisplayOrder, ISNULL(ac.ActorCount, 0) DESC, t.Name;
END;
GO

/* ---------------------------------------------------------------------
   sp_ImportAttackBundle: MITRE ATT&CK anlık görüntüsünü (JSON) yükler.
   MERGE ile tekrar çalıştırılabilir (idempotent): var olanı günceller,
   olmayanı ekler. Tamamı tek transaction.
   --------------------------------------------------------------------- */
CREATE OR ALTER PROCEDURE dbo.sp_ImportAttackBundle @Json NVARCHAR(MAX)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    BEGIN TRY
        EXEC sys.sp_set_session_context @key = N'skip_audit', @value = 1;
        BEGIN TRANSACTION;

        /* Taktikler */
        MERGE dbo.Tactic AS t
        USING (SELECT * FROM OPENJSON(@Json, '$.tactics') WITH (
                   id VARCHAR(10) '$.id', short VARCHAR(50) '$.short', name NVARCHAR(100) '$.name',
                   [desc] NVARCHAR(1000) '$.desc', ord TINYINT '$.order')) AS s
        ON t.ExternalID = s.id
        WHEN MATCHED THEN UPDATE SET ShortName = s.short, Name = s.name, Description = s.[desc], DisplayOrder = s.ord
        WHEN NOT MATCHED THEN INSERT (ExternalID, ShortName, Name, Description, DisplayOrder)
                              VALUES (s.id, s.short, s.name, s.[desc], s.ord);

        /* Teknikler: önce kayıtlar, sonra üst teknik bağlantısı (özyinelemeli FK) */
        DECLARE @tech TABLE (id VARCHAR(12) PRIMARY KEY, name NVARCHAR(150), [desc] NVARCHAR(1500), parent VARCHAR(12), tactics NVARCHAR(MAX));
        INSERT INTO @tech
        SELECT id, name, [desc], parent, tactics
        FROM OPENJSON(@Json, '$.techniques') WITH (
            id VARCHAR(12) '$.id', name NVARCHAR(150) '$.name', [desc] NVARCHAR(1500) '$.desc',
            parent VARCHAR(12) '$.parent', tactics NVARCHAR(MAX) '$.tactics' AS JSON);

        MERGE dbo.Technique AS t
        USING @tech AS s ON t.ExternalID = s.id
        WHEN MATCHED THEN UPDATE SET Name = s.name, Description = s.[desc]
        WHEN NOT MATCHED THEN INSERT (ExternalID, Name, Description) VALUES (s.id, s.name, s.[desc]);

        UPDATE c SET c.ParentTechniqueID = p.TechniqueID
        FROM dbo.Technique AS c
        JOIN @tech AS s ON s.id = c.ExternalID AND s.parent IS NOT NULL
        JOIN dbo.Technique AS p ON p.ExternalID = s.parent;

        INSERT INTO dbo.TechniqueTactic (TechniqueID, TacticID)
        SELECT t.TechniqueID, ta.TacticID
        FROM @tech AS s
        CROSS APPLY OPENJSON(s.tactics) AS j
        JOIN dbo.Technique AS t ON t.ExternalID = s.id
        JOIN dbo.Tactic AS ta ON ta.ShortName = j.[value]
        WHERE NOT EXISTS (SELECT 1 FROM dbo.TechniqueTactic AS x WHERE x.TechniqueID = t.TechniqueID AND x.TacticID = ta.TacticID);

        /* Aktörler */
        DECLARE @actor TABLE (id VARCHAR(12) PRIMARY KEY, name NVARCHAR(100), [desc] NVARCHAR(2000), country CHAR(2), motivation TINYINT, aliases NVARCHAR(MAX));
        INSERT INTO @actor
        SELECT id, name, [desc], country, motivation, aliases
        FROM OPENJSON(@Json, '$.actors') WITH (
            id VARCHAR(12) '$.id', name NVARCHAR(100) '$.name', [desc] NVARCHAR(2000) '$.desc',
            country CHAR(2) '$.country', motivation TINYINT '$.motivation', aliases NVARCHAR(MAX) '$.aliases' AS JSON);

        MERGE dbo.ThreatActor AS t
        USING (SELECT a.id, a.name, a.[desc], a.motivation,
                      CASE WHEN EXISTS (SELECT 1 FROM dbo.Country AS c WHERE c.CountryCode = a.country) THEN a.country END AS country
               FROM @actor AS a) AS s
        ON t.ExternalID = s.id OR (t.ExternalID IS NULL AND t.Name = s.name)
        WHEN MATCHED THEN UPDATE SET ExternalID = s.id, Description = s.[desc],
                                     CountryCode = ISNULL(t.CountryCode, s.country),
                                     MotivationID = ISNULL(t.MotivationID, s.motivation),
                                     UpdatedAt = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN INSERT (ExternalID, Name, Description, CountryCode, MotivationID)
                              VALUES (s.id, s.name, s.[desc], s.country, s.motivation);

        INSERT INTO dbo.ActorAlias (ActorID, Alias)
        SELECT DISTINCT a.ActorID, LEFT(j.[value], 100)
        FROM @actor AS s
        CROSS APPLY OPENJSON(s.aliases) AS j
        JOIN dbo.ThreatActor AS a ON a.ExternalID = s.id
        WHERE j.[value] <> a.Name
          AND NOT EXISTS (SELECT 1 FROM dbo.ActorAlias AS x WHERE x.ActorID = a.ActorID AND x.Alias = LEFT(j.[value], 100));

        /* Zararlı yazılımlar ve araçlar */
        DECLARE @sw TABLE (id VARCHAR(12) PRIMARY KEY, name NVARCHAR(100), [desc] NVARCHAR(2000), typ VARCHAR(20), platforms NVARCHAR(200), aliases NVARCHAR(MAX));
        INSERT INTO @sw
        SELECT id, name, [desc], typ, platforms, aliases
        FROM OPENJSON(@Json, '$.software') WITH (
            id VARCHAR(12) '$.id', name NVARCHAR(100) '$.name', [desc] NVARCHAR(2000) '$.desc',
            typ VARCHAR(20) '$.type', platforms NVARCHAR(200) '$.platforms', aliases NVARCHAR(MAX) '$.aliases' AS JSON);

        MERGE dbo.Malware AS t
        USING (SELECT s.id, s.name, s.[desc], s.platforms,
                      ISNULL(mt.MalwareTypeID, (SELECT MalwareTypeID FROM dbo.MalwareType WHERE Code = 'malware')) AS MalwareTypeID
               FROM @sw AS s LEFT JOIN dbo.MalwareType AS mt ON mt.Code = s.typ) AS s
        ON t.ExternalID = s.id OR (t.ExternalID IS NULL AND t.Name = s.name)
        WHEN MATCHED THEN UPDATE SET ExternalID = s.id, Description = s.[desc], Platforms = s.platforms,
                                     MalwareTypeID = s.MalwareTypeID, UpdatedAt = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN INSERT (ExternalID, Name, Description, Platforms, MalwareTypeID)
                              VALUES (s.id, s.name, s.[desc], s.platforms, s.MalwareTypeID);

        INSERT INTO dbo.MalwareAlias (MalwareID, Alias)
        SELECT DISTINCT m.MalwareID, LEFT(j.[value], 100)
        FROM @sw AS s
        CROSS APPLY OPENJSON(s.aliases) AS j
        JOIN dbo.Malware AS m ON m.ExternalID = s.id
        WHERE j.[value] <> m.Name
          AND NOT EXISTS (SELECT 1 FROM dbo.MalwareAlias AS x WHERE x.MalwareID = m.MalwareID AND x.Alias = LEFT(j.[value], 100));

        /* Kampanyalar */
        MERGE dbo.Campaign AS t
        USING (SELECT c.id, c.name, c.[desc], c.first_seen, c.last_seen, a.ActorID
               FROM OPENJSON(@Json, '$.campaigns') WITH (
                        id VARCHAR(12) '$.id', name NVARCHAR(150) '$.name', [desc] NVARCHAR(2000) '$.desc',
                        first_seen DATE '$.first', last_seen DATE '$.last', actor VARCHAR(12) '$.actor') AS c
               LEFT JOIN dbo.ThreatActor AS a ON a.ExternalID = c.actor) AS s
        ON t.ExternalID = s.id OR (t.ExternalID IS NULL AND t.Name = s.name)
        WHEN MATCHED THEN UPDATE SET ExternalID = s.id, Description = s.[desc], StartDate = s.first_seen,
                                     EndDate = CASE WHEN s.last_seen >= s.first_seen THEN s.last_seen END,
                                     ActorID = ISNULL(s.ActorID, t.ActorID), UpdatedAt = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN INSERT (ExternalID, Name, Description, StartDate, EndDate, ActorID)
                              VALUES (s.id, s.name, s.[desc], s.first_seen,
                                      CASE WHEN s.last_seen >= s.first_seen THEN s.last_seen END, s.ActorID);

        /* İlişkiler: [kaynak, hedef, açıklama, STIX kimliği, kaynak URL] biçiminde.
           Her ilişkinin ATT&CK'teki açıklaması kanıt (Evidence) olarak saklanır. */
        DECLARE @rel TABLE (Kind VARCHAR(20) NOT NULL, A VARCHAR(12) NOT NULL, B VARCHAR(12) NOT NULL,
                            Descr NVARCHAR(1000) NULL, Ref VARCHAR(100) NULL, Url NVARCHAR(400) NULL);
        INSERT INTO @rel
        SELECT 'actor_software', a, b, d, r, u FROM OPENJSON(@Json, '$.rel.actor_software')
            WITH (a VARCHAR(12) '$[0]', b VARCHAR(12) '$[1]', d NVARCHAR(1000) '$[2]', r VARCHAR(100) '$[3]', u NVARCHAR(400) '$[4]')
        UNION ALL
        SELECT 'actor_technique', a, b, d, r, u FROM OPENJSON(@Json, '$.rel.actor_technique')
            WITH (a VARCHAR(12) '$[0]', b VARCHAR(12) '$[1]', d NVARCHAR(1000) '$[2]', r VARCHAR(100) '$[3]', u NVARCHAR(400) '$[4]')
        UNION ALL
        SELECT 'software_technique', a, b, d, r, u FROM OPENJSON(@Json, '$.rel.software_technique')
            WITH (a VARCHAR(12) '$[0]', b VARCHAR(12) '$[1]', d NVARCHAR(1000) '$[2]', r VARCHAR(100) '$[3]', u NVARCHAR(400) '$[4]')
        UNION ALL
        SELECT 'campaign_software', a, b, d, r, u FROM OPENJSON(@Json, '$.rel.campaign_software')
            WITH (a VARCHAR(12) '$[0]', b VARCHAR(12) '$[1]', d NVARCHAR(1000) '$[2]', r VARCHAR(100) '$[3]', u NVARCHAR(400) '$[4]')
        UNION ALL
        SELECT 'campaign_technique', a, b, d, r, u FROM OPENJSON(@Json, '$.rel.campaign_technique')
            WITH (a VARCHAR(12) '$[0]', b VARCHAR(12) '$[1]', d NVARCHAR(1000) '$[2]', r VARCHAR(100) '$[3]', u NVARCHAR(400) '$[4]')
        UNION ALL
        SELECT 'campaign_actor', a, b, d, r, u FROM OPENJSON(@Json, '$.rel.campaign_actor')
            WITH (a VARCHAR(12) '$[0]', b VARCHAR(12) '$[1]', d NVARCHAR(1000) '$[2]', r VARCHAR(100) '$[3]', u NVARCHAR(400) '$[4]');

        DECLARE @attackSource SMALLINT = (SELECT SourceID FROM dbo.Source WHERE Name = N'MITRE ATT&CK');

        MERGE dbo.Evidence AS t
        USING (SELECT Ref, MIN(ISNULL(NULLIF(Descr, N''), N'MITRE ATT&CK bu ilişkiyi belgeliyor.')) AS Descr, MIN(Url) AS Url
               FROM @rel WHERE Ref IS NOT NULL GROUP BY Ref) AS s
        ON t.ExternalRef = s.Ref
        WHEN MATCHED AND (t.Summary <> s.Descr OR ISNULL(t.Url, N'') <> ISNULL(s.Url, N''))
            THEN UPDATE SET Summary = s.Descr, Url = s.Url
        WHEN NOT MATCHED THEN INSERT (SourceID, Summary, Url, ExternalRef) VALUES (@attackSource, s.Descr, s.Url, s.Ref);

        INSERT INTO dbo.ActorMalware (ActorID, MalwareID, EvidenceID)
        SELECT a.ActorID, m.MalwareID, MIN(e.EvidenceID)
        FROM @rel AS r
        JOIN dbo.ThreatActor AS a ON a.ExternalID = r.A
        JOIN dbo.Malware AS m ON m.ExternalID = r.B
        LEFT JOIN dbo.Evidence AS e ON e.ExternalRef = r.Ref
        WHERE r.Kind = 'actor_software'
          AND NOT EXISTS (SELECT 1 FROM dbo.ActorMalware AS x WHERE x.ActorID = a.ActorID AND x.MalwareID = m.MalwareID)
        GROUP BY a.ActorID, m.MalwareID;

        INSERT INTO dbo.ActorTechnique (ActorID, TechniqueID, EvidenceID)
        SELECT a.ActorID, t.TechniqueID, MIN(e.EvidenceID)
        FROM @rel AS r
        JOIN dbo.ThreatActor AS a ON a.ExternalID = r.A
        JOIN dbo.Technique AS t ON t.ExternalID = r.B
        LEFT JOIN dbo.Evidence AS e ON e.ExternalRef = r.Ref
        WHERE r.Kind = 'actor_technique'
          AND NOT EXISTS (SELECT 1 FROM dbo.ActorTechnique AS x WHERE x.ActorID = a.ActorID AND x.TechniqueID = t.TechniqueID)
        GROUP BY a.ActorID, t.TechniqueID;

        INSERT INTO dbo.MalwareTechnique (MalwareID, TechniqueID, EvidenceID)
        SELECT m.MalwareID, t.TechniqueID, MIN(e.EvidenceID)
        FROM @rel AS r
        JOIN dbo.Malware AS m ON m.ExternalID = r.A
        JOIN dbo.Technique AS t ON t.ExternalID = r.B
        LEFT JOIN dbo.Evidence AS e ON e.ExternalRef = r.Ref
        WHERE r.Kind = 'software_technique'
          AND NOT EXISTS (SELECT 1 FROM dbo.MalwareTechnique AS x WHERE x.MalwareID = m.MalwareID AND x.TechniqueID = t.TechniqueID)
        GROUP BY m.MalwareID, t.TechniqueID;

        INSERT INTO dbo.CampaignMalware (CampaignID, MalwareID, EvidenceID)
        SELECT c.CampaignID, m.MalwareID, MIN(e.EvidenceID)
        FROM @rel AS r
        JOIN dbo.Campaign AS c ON c.ExternalID = r.A
        JOIN dbo.Malware AS m ON m.ExternalID = r.B
        LEFT JOIN dbo.Evidence AS e ON e.ExternalRef = r.Ref
        WHERE r.Kind = 'campaign_software'
          AND NOT EXISTS (SELECT 1 FROM dbo.CampaignMalware AS x WHERE x.CampaignID = c.CampaignID AND x.MalwareID = m.MalwareID)
        GROUP BY c.CampaignID, m.MalwareID;

        INSERT INTO dbo.CampaignTechnique (CampaignID, TechniqueID, EvidenceID)
        SELECT c.CampaignID, t.TechniqueID, MIN(e.EvidenceID)
        FROM @rel AS r
        JOIN dbo.Campaign AS c ON c.ExternalID = r.A
        JOIN dbo.Technique AS t ON t.ExternalID = r.B
        LEFT JOIN dbo.Evidence AS e ON e.ExternalRef = r.Ref
        WHERE r.Kind = 'campaign_technique'
          AND NOT EXISTS (SELECT 1 FROM dbo.CampaignTechnique AS x WHERE x.CampaignID = c.CampaignID AND x.TechniqueID = t.TechniqueID)
        GROUP BY c.CampaignID, t.TechniqueID;

        -- Kampanya atfı: ActorID kampanya kaydında; kanıtı AttributionEvidenceID
        UPDATE c SET c.AttributionEvidenceID = e.EvidenceID
        FROM dbo.Campaign AS c
        JOIN @rel AS r ON r.Kind = 'campaign_actor' AND r.A = c.ExternalID
        JOIN dbo.ThreatActor AS a ON a.ExternalID = r.B AND a.ActorID = c.ActorID
        JOIN dbo.Evidence AS e ON e.ExternalRef = r.Ref
        WHERE ISNULL(c.AttributionEvidenceID, 0) <> e.EvidenceID;

        COMMIT TRANSACTION;
        EXEC sys.sp_set_session_context @key = N'skip_audit', @value = NULL;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        EXEC sys.sp_set_session_context @key = N'skip_audit', @value = NULL;
        THROW;
    END CATCH;

    EXEC dbo.sp_RefreshActorSimilarity;

    SELECT (SELECT COUNT(*) FROM dbo.Tactic) AS Tactics, (SELECT COUNT(*) FROM dbo.Technique) AS Techniques,
           (SELECT COUNT(*) FROM dbo.ThreatActor) AS Actors, (SELECT COUNT(*) FROM dbo.Malware) AS Malware,
           (SELECT COUNT(*) FROM dbo.Campaign) AS Campaigns, (SELECT COUNT(*) FROM dbo.Evidence) AS Evidence;
END;
GO

/* Kullanıcının tüm oturumlarını kapatır (devre dışı bırakma, parola değişimi).
   UserSession tablosu uygulama rollerine kapalıdır (DENY); erişim yalnızca bu yordam üzerinden olur
   (sahiplik zinciri: yordam ve tablo dbo'ya ait olduğu için tablo izni ayrıca denetlenmez). */
CREATE OR ALTER PROCEDURE dbo.sp_EndUserSessions @UserID INT
AS
BEGIN
    SET NOCOUNT ON;
    DELETE FROM dbo.UserSession WHERE UserID = @UserID;
    SELECT @@ROWCOUNT AS EndedSessions;
END;
GO
