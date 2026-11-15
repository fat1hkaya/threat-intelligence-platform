/* =====================================================================
   ThreatLens - 14: Log'dan geriye dönük av (retro-hunt)
   Tekrar çalıştırılabilir.
   ---------------------------------------------------------------------
   Analist güvenlik duvarı / proxy / DNS logunu yapıştırır. Uygulama katmanı (app/services/hunt.py)
   IOC adaylarını ayıklayıp kanonik biçime getirir; eşleme burada TEK bir set tabanlı sorguyla,
   UQ_Indicator_Type_Normalized (TypeID, NormalizedValue) indeksi üzerinden yapılır.
     HuntRun   : her av (kim, ne zaman, nerede, kaç satır/aday/eşleşme)
     HuntMatch : avın eşleştirdiği IOC'ler (M:N: bir av birçok IOC, bir IOC birçok av)
     Sighting  : analist "görülme olarak kaydet" derse; HuntID ile hangi avdan geldiği bilinir.
                 trg_Sighting_AfterInsert IOC'nin son görülme ve geçerlilik süresini uzatır.
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'dbo.HuntRun') IS NULL
BEGIN
    CREATE TABLE dbo.HuntRun (
        HuntID       INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_HuntRun PRIMARY KEY,
        StartedBy    INT NULL CONSTRAINT FK_HuntRun_AppUser REFERENCES dbo.AppUser(UserID),
        StartedAt    DATETIME2(0)  NOT NULL CONSTRAINT DF_HuntRun_StartedAt DEFAULT (SYSUTCDATETIME()),
        Location     NVARCHAR(100) NOT NULL,                  -- logun geldiği yer: "Proxy / FW-01"
        FileName     NVARCHAR(200) NULL,
        LinesScanned INT NOT NULL,
        Candidates   INT NOT NULL,
        Matches      INT NOT NULL CONSTRAINT DF_HuntRun_Matches DEFAULT (0),
        Recorded     BIT NOT NULL CONSTRAINT DF_HuntRun_Recorded DEFAULT (0),   -- eşleşmeler görülme olarak yazıldı mı
        CONSTRAINT CK_HuntRun_Counts CHECK (LinesScanned >= 0 AND Candidates >= 0 AND Matches >= 0 AND Matches <= Candidates)
    );
    EXEC(N'CREATE INDEX IX_HuntRun_StartedAt ON dbo.HuntRun (StartedAt DESC);');
END;
GO
IF OBJECT_ID(N'dbo.HuntMatch') IS NULL
BEGIN
    CREATE TABLE dbo.HuntMatch (
        HuntID      INT    NOT NULL CONSTRAINT FK_HuntMatch_HuntRun REFERENCES dbo.HuntRun(HuntID) ON DELETE CASCADE,
        IndicatorID BIGINT NOT NULL CONSTRAINT FK_HuntMatch_Indicator REFERENCES dbo.Indicator(IndicatorID) ON DELETE CASCADE,
        MatchKind   VARCHAR(6)    NOT NULL,                    -- exact: birebir, host: URL'nin ana bilgisayarı, parent: üst domain
        Hits        INT           NOT NULL,
        FirstLine   INT           NOT NULL,
        LogValue    NVARCHAR(400) NOT NULL,                    -- logda geçtiği biçim (ör. hxxp://kotu[.]example/a)
        SampleLine  NVARCHAR(300) NULL,
        CONSTRAINT PK_HuntMatch PRIMARY KEY (HuntID, IndicatorID),
        CONSTRAINT CK_HuntMatch_Kind CHECK (MatchKind IN ('exact', 'host', 'parent')),
        CONSTRAINT CK_HuntMatch_Hits CHECK (Hits > 0 AND FirstLine > 0)
    );
    EXEC(N'CREATE INDEX IX_HuntMatch_Indicator ON dbo.HuntMatch (IndicatorID);');
END;
GO
IF COL_LENGTH(N'dbo.Sighting', N'HuntID') IS NULL
BEGIN
    ALTER TABLE dbo.Sighting ADD HuntID INT NULL CONSTRAINT FK_Sighting_HuntRun REFERENCES dbo.HuntRun(HuntID) ON DELETE SET NULL;
    EXEC(N'CREATE INDEX IX_Sighting_Hunt ON dbo.Sighting (HuntID) WHERE HuntID IS NOT NULL;');
END;
GO

/* @Json: [{"type":"domain","value":"kotu.example","kind":"exact","source":"kotu[.]example","hits":3,"line":12,"sample":"..."}]
   İki sonuç kümesi döner: eşleşen IOC'ler (risk ve atıf özetiyle) ve av özeti. */
CREATE OR ALTER PROCEDURE dbo.sp_RetroHunt
    @Json      NVARCHAR(MAX),
    @Location  NVARCHAR(100),
    @Lines     INT,
    @FileName  NVARCHAR(200) = NULL,
    @Record    BIT = 0,
    @UserID    INT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    -- Savunma derinliği: görülme yazmak analist yetkisi ister (uygulama da ayrıca denetler)
    IF @Record = 1 AND IS_MEMBER('tip_analyst') = 0 AND IS_SRVROLEMEMBER('sysadmin') = 0
        THROW 50050, N'Eşleşmeleri görülme olarak kaydetmek için analist yetkisi gerekir.', 1;
    IF LEN(LTRIM(RTRIM(ISNULL(@Location, N'')))) = 0
        THROW 50051, N'Logun geldiği yeri (ör. Proxy / FW-01) belirtin.', 1;

    DECLARE @c TABLE (TypeCode VARCHAR(10), Value NVARCHAR(400), MatchKind VARCHAR(6), LogValue NVARCHAR(400),
                      Hits INT, FirstLine INT, SampleLine NVARCHAR(300));
    INSERT INTO @c
    SELECT j.[type], j.[value], j.kind, j.[source], j.hits, j.line, j.sample
    FROM OPENJSON(@Json) WITH ([type] VARCHAR(10) '$.type', [value] NVARCHAR(400) '$.value', kind VARCHAR(6) '$.kind',
                               [source] NVARCHAR(400) '$.source', hits INT '$.hits', line INT '$.line', sample NVARCHAR(300) '$.sample') AS j;

    -- Tek set tabanlı eşleme: UQ (TypeID, NormalizedValue) indeksi üzerinden
    DECLARE @m TABLE (IndicatorID BIGINT PRIMARY KEY, MatchKind VARCHAR(6), Hits INT, FirstLine INT, LogValue NVARCHAR(400), SampleLine NVARCHAR(300));
    INSERT INTO @m
    SELECT x.IndicatorID, x.MatchKind, x.Hits, x.FirstLine, x.LogValue, x.SampleLine
    FROM (
        SELECT i.IndicatorID, c.MatchKind, c.Hits, c.FirstLine, c.LogValue, c.SampleLine,
               ROW_NUMBER() OVER (PARTITION BY i.IndicatorID
                                  ORDER BY CASE c.MatchKind WHEN 'exact' THEN 1 WHEN 'host' THEN 2 ELSE 3 END, c.FirstLine) AS rn
        FROM @c AS c
        JOIN dbo.IndicatorType AS t ON t.Code = c.TypeCode
        JOIN dbo.Indicator AS i ON i.TypeID = t.TypeID AND i.NormalizedValue = c.Value
    ) AS x
    WHERE x.rn = 1;

    DECLARE @hunt INT, @matches INT = (SELECT COUNT(*) FROM @m);
    BEGIN TRANSACTION;
    INSERT INTO dbo.HuntRun (StartedBy, Location, FileName, LinesScanned, Candidates, Matches, Recorded)
    VALUES (@UserID, LEFT(@Location, 100), @FileName, @Lines, (SELECT COUNT(*) FROM @c), @matches, @Record);
    SET @hunt = SCOPE_IDENTITY();

    INSERT INTO dbo.HuntMatch (HuntID, IndicatorID, MatchKind, Hits, FirstLine, LogValue, SampleLine)
    SELECT @hunt, IndicatorID, MatchKind, Hits, FirstLine, LogValue, SampleLine FROM @m;

    IF @Record = 1
        INSERT INTO dbo.Sighting (IndicatorID, SightedAt, Quantity, Location, Note, ReportedBy, HuntID)
        SELECT IndicatorID, SYSUTCDATETIME(), Hits, LEFT(@Location, 100), CONCAT(N'Log avı #', @hunt, N', satır ', FirstLine), @UserID, @hunt
        FROM @m;                                  -- trg_Sighting_AfterInsert: LastSeen ve ExpiresAt uzar, süresi dolmuş IOC etkinleşir
    COMMIT TRANSACTION;

    EXEC dbo.sp_HuntResult @HuntID = @hunt;
END;
GO

/* Bir avın sonucu (yeni av veya geçmişteki av için aynı biçim) */
CREATE OR ALTER PROCEDURE dbo.sp_HuntResult @HuntID INT
AS
BEGIN
    SET NOCOUNT ON;
    SELECT hm.IndicatorID, v.Value, v.TypeCode, v.SeverityCode, v.Confidence, v.RiskScore, v.Status, v.SourceName,
           hm.MatchKind, hm.Hits, hm.FirstLine, hm.LogValue, hm.SampleLine,
           a.ViaName AS MalwareName, a.ActorName
    FROM dbo.HuntMatch AS hm
    JOIN dbo.vw_Indicator AS v ON v.IndicatorID = hm.IndicatorID
    OUTER APPLY (SELECT TOP (1) x.ViaName, x.ActorName FROM dbo.vw_IndicatorAttribution AS x       -- MATCH tabanlı atıf
                 WHERE x.IndicatorID = hm.IndicatorID ORDER BY CASE WHEN x.ActorName IS NULL THEN 1 ELSE 0 END, x.ViaType DESC) AS a
    WHERE hm.HuntID = @HuntID
    ORDER BY v.RiskScore DESC, hm.Hits DESC;

    SELECT h.HuntID, h.StartedAt, h.Location, h.FileName, h.LinesScanned, h.Candidates, h.Matches, h.Recorded,
           u.FullName AS StartedBy,
           (SELECT COUNT(DISTINCT x.ActorID) FROM dbo.HuntMatch AS m JOIN dbo.vw_IndicatorAttribution AS x ON x.IndicatorID = m.IndicatorID
             WHERE m.HuntID = h.HuntID AND x.ActorID IS NOT NULL) AS Actors,
           (SELECT COUNT(*) FROM dbo.HuntMatch AS m JOIN dbo.Indicator AS i ON i.IndicatorID = m.IndicatorID
              JOIN dbo.SeverityLevel AS s ON s.SeverityID = i.SeverityID WHERE m.HuntID = h.HuntID AND s.Code IN ('high', 'critical')) AS HighRisk
    FROM dbo.HuntRun AS h LEFT JOIN dbo.AppUser AS u ON u.UserID = h.StartedBy
    WHERE h.HuntID = @HuntID;
END;
GO

GRANT EXECUTE ON dbo.sp_RetroHunt TO tip_reader;      -- izleyici arayabilir; kaydetme yordam içinde analiste sınırlı
GRANT EXECUTE ON dbo.sp_HuntResult TO tip_reader;
GO
