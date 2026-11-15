/* =====================================================================
   ThreatLens - 20: IP ağ zenginleştirme (ASN / ülke) ve altyapı örtüşmesi
   Tekrar çalıştırılabilir.
   ---------------------------------------------------------------------
   Kaynak: iptoasn.com ip2asn-v4 veri seti (Public Domain, PDDL v1.0), saatlik güncellenir.
     python -m importers ip2asn    -> yaklaşık 500 bin IP aralığı IpRange tablosuna yüklenir.
   AutonomousSystem : ASN -> kurum adı                                   (1)
   IpRange          : [StartIP, EndIP] -> ASN, ülke  (IPv4 tamsayı)       (N:1 AutonomousSystem)
   IndicatorNetwork : IPv4 IOC -> sayısal adres, ASN, ülke                (1:1 Indicator, ON DELETE CASCADE)
     IOC tablosuna ASN sütunu eklenmedi: yalnızca IP tipindeki IOC'ler için anlamlıdır (domain/hash satırlarında
     hep NULL olurdu) ve aralık verisi yenilendiğinde IOC satırları değil yalnızca bu tablo güncellenir.
   Aralık araması: aralıklar çakışmadığı için "StartIP <= ip olan EN BÜYÜK StartIP" tek bir indeks
     aramasıyla (TOP (1) ... ORDER BY StartIP DESC) bulunur; ardından ip <= EndIP denetlenir.
     500 bin satırlık tabloda IOC başına birkaç mantıksal okuma (BETWEEN ile tam tarama yerine).
   /24 alt ağ örtüşmesi aralık verisi gerektirmez: aynı /24 içindeki farklı ailelerin IOC'leri
     (IpNum / 256 aynı) paylaşılan barındırma altyapısına işaret eder.
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* Noktalı IPv4 -> 0..4294967295; geçersiz girişte NULL. Deterministik (SCHEMABINDING), satır içine alınabilir. */
CREATE OR ALTER FUNCTION dbo.fn_Ipv4ToBigint (@ip VARCHAR(45))
RETURNS BIGINT
WITH SCHEMABINDING
AS
BEGIN
    IF @ip IS NULL OR @ip LIKE '%[^0-9.]%' OR LEN(@ip) - LEN(REPLACE(@ip, '.', '')) <> 3 RETURN NULL;
    DECLARE @a BIGINT = TRY_CAST(PARSENAME(@ip, 4) AS BIGINT), @b BIGINT = TRY_CAST(PARSENAME(@ip, 3) AS BIGINT),
            @c BIGINT = TRY_CAST(PARSENAME(@ip, 2) AS BIGINT), @d BIGINT = TRY_CAST(PARSENAME(@ip, 1) AS BIGINT);
    IF @a > 255 OR @b > 255 OR @c > 255 OR @d > 255 RETURN NULL;
    RETURN ((@a * 256 + @b) * 256 + @c) * 256 + @d;
END;
GO
CREATE OR ALTER FUNCTION dbo.fn_BigintToIpv4 (@n BIGINT)
RETURNS VARCHAR(15)
WITH SCHEMABINDING
AS
BEGIN
    RETURN CONCAT(@n / 16777216 % 256, '.', @n / 65536 % 256, '.', @n / 256 % 256, '.', @n % 256);
END;
GO

IF OBJECT_ID(N'dbo.AutonomousSystem') IS NULL
    CREATE TABLE dbo.AutonomousSystem (
        ASN         BIGINT        NOT NULL CONSTRAINT PK_AutonomousSystem PRIMARY KEY,
        Name        NVARCHAR(200) NOT NULL,
        CountryCode CHAR(2)       NULL,          -- ISO 3166-1; Country tablosu yalnızca aktör kökenlerini tutar, FK yok
        CONSTRAINT CK_AutonomousSystem_ASN CHECK (ASN BETWEEN 1 AND 4294967295),
        CONSTRAINT CK_AutonomousSystem_Country CHECK (CountryCode LIKE '[A-Z][A-Z]')
    );
GO
IF OBJECT_ID(N'dbo.IpRange') IS NULL
    CREATE TABLE dbo.IpRange (
        StartIP     BIGINT  NOT NULL CONSTRAINT PK_IpRange PRIMARY KEY,       -- kümelenmiş: aralık araması için
        EndIP       BIGINT  NOT NULL,
        ASN         BIGINT  NOT NULL CONSTRAINT FK_IpRange_AutonomousSystem REFERENCES dbo.AutonomousSystem(ASN),
        CountryCode CHAR(2) NULL,
        CONSTRAINT CK_IpRange_Order CHECK (EndIP >= StartIP AND StartIP >= 0 AND EndIP <= 4294967295),
        CONSTRAINT CK_IpRange_Country CHECK (CountryCode LIKE '[A-Z][A-Z]')
    );
GO
IF OBJECT_ID(N'dbo.IndicatorNetwork') IS NULL
BEGIN
    CREATE TABLE dbo.IndicatorNetwork (
        IndicatorID BIGINT NOT NULL CONSTRAINT PK_IndicatorNetwork PRIMARY KEY
                    CONSTRAINT FK_IndicatorNetwork_Indicator REFERENCES dbo.Indicator(IndicatorID) ON DELETE CASCADE,
        IpNum       BIGINT  NOT NULL,
        ASN         BIGINT  NULL CONSTRAINT FK_IndicatorNetwork_AutonomousSystem REFERENCES dbo.AutonomousSystem(ASN),
        CountryCode CHAR(2) NULL,
        EnrichedAt  DATETIME2(0) NULL,
        CONSTRAINT CK_IndicatorNetwork_Ip CHECK (IpNum BETWEEN 0 AND 4294967295)
    );
    EXEC(N'CREATE INDEX IX_IndicatorNetwork_IpNum ON dbo.IndicatorNetwork (IpNum) INCLUDE (ASN);');
    EXEC(N'CREATE INDEX IX_IndicatorNetwork_ASN ON dbo.IndicatorNetwork (ASN) INCLUDE (IpNum, CountryCode);');
END;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.Source WHERE Name = N'iptoasn.com')
    INSERT INTO dbo.Source (Name, Url, Reliability, Description)
    VALUES (N'iptoasn.com', N'https://iptoasn.com', 'B',
            N'IP aralığı -> ASN ve ülke eşlemesi (ip2asn-v4, Public Domain PDDL v1.0). IOC üretmez, IP IOC''lerini zenginleştirir.');
GO

/* Verilen IOC'lerin ağ bilgisini hesaplar (tek küme sorgusu). @All = 1: tüm IPv4 IOC'ler (aralık verisi yenilendiğinde). */
CREATE OR ALTER PROCEDURE dbo.sp_EnrichNetwork @All BIT = 0, @IdsJson NVARCHAR(MAX) = NULL, @Quiet BIT = 0
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @run INT, @n INT = 0;
    IF @All = 1
    BEGIN
        INSERT INTO dbo.MaintenanceRun (Task) VALUES ('network-enrichment');
        SET @run = SCOPE_IDENTITY();
    END;
    BEGIN TRY
        DECLARE @ids TABLE (IndicatorID BIGINT PRIMARY KEY, IpNum BIGINT NOT NULL);
        INSERT INTO @ids (IndicatorID, IpNum)
        SELECT i.IndicatorID, dbo.fn_Ipv4ToBigint(i.NormalizedValue)
        FROM dbo.Indicator AS i
        JOIN dbo.IndicatorType AS t ON t.TypeID = i.TypeID AND t.Code = 'ipv4'
        WHERE (@All = 1 OR i.IndicatorID IN (SELECT CAST([value] AS BIGINT) FROM OPENJSON(@IdsJson)))
          AND dbo.fn_Ipv4ToBigint(i.NormalizedValue) IS NOT NULL;

        MERGE dbo.IndicatorNetwork AS n
        USING (
            SELECT x.IndicatorID, x.IpNum,
                   CASE WHEN r.EndIP >= x.IpNum THEN r.ASN END AS ASN,
                   CASE WHEN r.EndIP >= x.IpNum THEN r.CountryCode END AS CountryCode
            FROM @ids AS x
            OUTER APPLY (SELECT TOP (1) g.EndIP, g.ASN, g.CountryCode FROM dbo.IpRange AS g
                         WHERE g.StartIP <= x.IpNum ORDER BY g.StartIP DESC) AS r      -- tek indeks araması
        ) AS s ON s.IndicatorID = n.IndicatorID
        WHEN MATCHED AND (n.IpNum <> s.IpNum OR EXISTS (SELECT n.ASN, n.CountryCode EXCEPT SELECT s.ASN, s.CountryCode)) THEN
            UPDATE SET IpNum = s.IpNum, ASN = s.ASN, CountryCode = s.CountryCode, EnrichedAt = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN
            INSERT (IndicatorID, IpNum, ASN, CountryCode, EnrichedAt) VALUES (s.IndicatorID, s.IpNum, s.ASN, s.CountryCode, SYSUTCDATETIME());
        SET @n = @@ROWCOUNT;
        -- tipi IP olmaktan çıkan ya da değeri bozulan IOC'lerin ağ kaydı kalmasın
        DELETE n FROM dbo.IndicatorNetwork AS n
        WHERE (@All = 1 OR n.IndicatorID IN (SELECT CAST([value] AS BIGINT) FROM OPENJSON(@IdsJson)))
          AND NOT EXISTS (SELECT 1 FROM @ids AS x WHERE x.IndicatorID = n.IndicatorID);
        SET @n += @@ROWCOUNT;
        IF @run IS NOT NULL
            UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), RowsAffected = @n, Status = 'success',
                   Message = CONCAT((SELECT COUNT(*) FROM dbo.IndicatorNetwork WHERE ASN IS NOT NULL), N' IP IOC ASN ile eşlendi')
            WHERE RunID = @run;
    END TRY
    BEGIN CATCH
        IF @run IS NOT NULL
            UPDATE dbo.MaintenanceRun SET FinishedAt = SYSUTCDATETIME(), Status = 'failed', Message = LEFT(ERROR_MESSAGE(), 400) WHERE RunID = @run;
        THROW;
    END CATCH;
    IF @Quiet = 0 SELECT @n AS RowsAffected;   -- tetikleyiciden çağrıda sonuç kümesi yok (iç içe INSERT-EXEC olmasın)
END;
GO

/* Yeni/değişen IP IOC'leri anında zenginleştirilir (elle giriş, besleme, API). Küme tabanlı: toplu içe aktarımda da tek çağrı. */
CREATE OR ALTER TRIGGER dbo.trg_Indicator_Network ON dbo.Indicator AFTER INSERT, UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF UPDATE(NormalizedValue) OR UPDATE(TypeID) OR NOT EXISTS (SELECT 1 FROM deleted)
    BEGIN
        DECLARE @ids NVARCHAR(MAX) = (SELECT CONCAT('[', STRING_AGG(CAST(IndicatorID AS VARCHAR(MAX)), ','), ']') FROM inserted);
        EXEC dbo.sp_EnrichNetwork @All = 0, @IdsJson = @ids, @Quiet = 1;
    END;
END;
GO

/* IP aralığı yükleme: çağıran oturumdaki #ip2asn geçici tablosundan (StartIP, EndIP, ASN, CountryCode, Name).
   Tek işlemde değiştirilir: yükleme yarıda kalırsa eski aralıklar korunur. */
CREATE OR ALTER PROCEDURE dbo.sp_LoadIpRanges @JobID INT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @read INT = (SELECT COUNT(*) FROM #ip2asn), @asn INT, @ranges INT;
    BEGIN TRANSACTION;
        -- AS adı: aynı ASN'nin satırlarından en sık geçen ad (veri setinde tutarlıdır, yine de tekilleştirilir)
        MERGE dbo.AutonomousSystem AS a
        USING (
            SELECT ASN, Name, CountryCode FROM (
                SELECT ASN, LEFT(Name, 200) AS Name, CASE WHEN CountryCode LIKE '[A-Z][A-Z]' THEN CountryCode END AS CountryCode,
                       ROW_NUMBER() OVER (PARTITION BY ASN ORDER BY COUNT(*) DESC, Name) AS rn
                FROM #ip2asn WHERE ASN BETWEEN 1 AND 4294967295
                GROUP BY ASN, Name, CountryCode) AS x
            WHERE rn = 1
        ) AS s ON s.ASN = a.ASN
        WHEN MATCHED AND EXISTS (SELECT a.Name, a.CountryCode EXCEPT SELECT s.Name, s.CountryCode) THEN
            UPDATE SET Name = s.Name, CountryCode = s.CountryCode
        WHEN NOT MATCHED THEN INSERT (ASN, Name, CountryCode) VALUES (s.ASN, s.Name, s.CountryCode);
        SET @asn = @@ROWCOUNT;
        DELETE FROM dbo.IpRange;
        INSERT INTO dbo.IpRange (StartIP, EndIP, ASN, CountryCode)
        SELECT StartIP, EndIP, ASN, CASE WHEN CountryCode LIKE '[A-Z][A-Z]' THEN CountryCode END
        FROM #ip2asn WHERE ASN BETWEEN 1 AND 4294967295 AND EndIP >= StartIP;    -- ASN 0 = yönlendirilmeyen blok
        SET @ranges = @@ROWCOUNT;
        IF @JobID IS NOT NULL
            UPDATE dbo.ImportJob SET RowsRead = @read, RowsInserted = @ranges, RowsUpdated = @asn, RowsSkipped = @read - @ranges WHERE JobID = @JobID;
    COMMIT;
    EXEC dbo.sp_EnrichNetwork @All = 1, @Quiet = 1;
    SELECT @read AS RowsRead, @ranges AS Ranges, @asn AS AsChanged,
           (SELECT COUNT(*) FROM dbo.IndicatorNetwork WHERE ASN IS NOT NULL) AS EnrichedIOCs;
END;
GO

CREATE OR ALTER VIEW dbo.vw_IndicatorNetwork
AS
SELECT n.IndicatorID, i.NormalizedValue AS Value, n.IpNum,
       CONCAT(dbo.fn_BigintToIpv4(n.IpNum / 256 * 256), '/24') AS Subnet24,
       n.ASN, a.Name AS ASName, n.CountryCode, c.Name AS CountryName, n.EnrichedAt, i.Status
FROM dbo.IndicatorNetwork AS n
JOIN dbo.Indicator AS i ON i.IndicatorID = n.IndicatorID
LEFT JOIN dbo.AutonomousSystem AS a ON a.ASN = n.ASN
LEFT JOIN dbo.Country AS c ON c.CountryCode = n.CountryCode;
GO

/* Altyapı örtüşmesi: farklı zararlı ailelerinin IOC'lerini barındıran ASN'ler ve /24 alt ağlar.
   Aile ve aktör sayıları IOC -> zararlı (MalwareIndicator) -> aktör (ActorMalware) zinciriyle bulunur. */
CREATE OR ALTER PROCEDURE dbo.sp_InfrastructureOverlap @MinFamilies INT = 2, @Top INT = 30
AS
BEGIN
    SET NOCOUNT ON;
    -- IP IOC'leri ve aileleri bir kez hesaplanır
    SELECT n.IndicatorID, n.IpNum, n.IpNum / 256 AS Net24, n.ASN, n.CountryCode, i.Status, mi.MalwareID
    INTO #x
    FROM dbo.IndicatorNetwork AS n
    JOIN dbo.Indicator AS i ON i.IndicatorID = n.IndicatorID
    LEFT JOIN dbo.MalwareIndicator AS mi ON mi.IndicatorID = n.IndicatorID;

    -- 1) özet
    SELECT (SELECT COUNT(*) FROM dbo.IndicatorNetwork) AS IpIOCs,
           (SELECT COUNT(*) FROM dbo.IndicatorNetwork WHERE ASN IS NOT NULL) AS Enriched,
           (SELECT COUNT(*) FROM dbo.IpRange) AS Ranges,
           (SELECT COUNT(DISTINCT ASN) FROM dbo.IndicatorNetwork) AS DistinctASNs,
           (SELECT MAX(FinishedAt) FROM dbo.ImportJob AS j JOIN dbo.Source AS s ON s.SourceID = j.SourceID
             WHERE s.Name = N'iptoasn.com' AND j.Status = 'success') AS RangesLoadedAt;

    -- 2) ASN'ler: en çok aileye ev sahipliği yapan
    SELECT TOP (@Top) g.ASN, a.Name AS ASName, a.CountryCode, g.IOCs, g.ActiveIOCs, g.Families, g.Actors,
           (SELECT STRING_AGG(m.Name, ', ') WITHIN GROUP (ORDER BY m.Name)
              FROM (SELECT DISTINCT MalwareID FROM #x WHERE ASN = g.ASN AND MalwareID IS NOT NULL) AS d
              JOIN dbo.Malware AS m ON m.MalwareID = d.MalwareID) AS FamilyNames
    FROM (
        SELECT x.ASN, COUNT(DISTINCT x.IndicatorID) AS IOCs,
               COUNT(DISTINCT CASE WHEN x.Status = 'active' THEN x.IndicatorID END) AS ActiveIOCs,
               COUNT(DISTINCT x.MalwareID) AS Families,
               (SELECT COUNT(DISTINCT am.ActorID) FROM #x AS y JOIN dbo.ActorMalware AS am ON am.MalwareID = y.MalwareID WHERE y.ASN = x.ASN) AS Actors
        FROM #x AS x WHERE x.ASN IS NOT NULL GROUP BY x.ASN
    ) AS g
    JOIN dbo.AutonomousSystem AS a ON a.ASN = g.ASN
    WHERE g.Families >= @MinFamilies OR g.IOCs >= 5
    ORDER BY g.Families DESC, g.IOCs DESC;

    -- 3) /24 alt ağlar: birden çok IOC, tercihen birden çok aile (aralık verisi gerekmez)
    SELECT TOP (@Top) CONCAT(dbo.fn_BigintToIpv4(g.Net24 * 256), '/24') AS Subnet, g.IOCs, g.Families,
           (SELECT TOP (1) a.Name FROM #x AS y JOIN dbo.AutonomousSystem AS a ON a.ASN = y.ASN WHERE y.Net24 = g.Net24) AS ASName,
           (SELECT STRING_AGG(m.Name, ', ') WITHIN GROUP (ORDER BY m.Name)
              FROM (SELECT DISTINCT MalwareID FROM #x WHERE Net24 = g.Net24 AND MalwareID IS NOT NULL) AS d
              JOIN dbo.Malware AS m ON m.MalwareID = d.MalwareID) AS FamilyNames,
           (SELECT STRING_AGG(CAST(y.IndicatorID AS VARCHAR(20)), ',') FROM (SELECT DISTINCT IndicatorID FROM #x WHERE Net24 = g.Net24) AS y) AS IndicatorIDs
    FROM (SELECT Net24, COUNT(DISTINCT IndicatorID) AS IOCs, COUNT(DISTINCT MalwareID) AS Families FROM #x GROUP BY Net24) AS g
    WHERE g.IOCs >= 2
    ORDER BY g.Families DESC, g.IOCs DESC;

    -- 4) ülke dağılımı
    SELECT x.CountryCode, COUNT(DISTINCT x.IndicatorID) AS IOCs, COUNT(DISTINCT x.MalwareID) AS Families
    FROM #x AS x WHERE x.CountryCode IS NOT NULL
    GROUP BY x.CountryCode ORDER BY IOCs DESC;
END;
GO

/* Tek IOC'nin ağ komşuları: aynı /24 ve aynı ASN'deki diğer IOC'ler */
CREATE OR ALTER PROCEDURE dbo.sp_IndicatorNetwork @IndicatorID BIGINT
AS
BEGIN
    SET NOCOUNT ON;
    SELECT v.* , (SELECT COUNT(*) FROM dbo.IndicatorNetwork AS o WHERE o.ASN = v.ASN) AS SameASN,
           (SELECT COUNT(*) FROM dbo.IndicatorNetwork AS o WHERE o.IpNum / 256 = v.IpNum / 256) AS SameSubnet
    FROM dbo.vw_IndicatorNetwork AS v WHERE v.IndicatorID = @IndicatorID;
    DECLARE @ip BIGINT = (SELECT IpNum FROM dbo.IndicatorNetwork WHERE IndicatorID = @IndicatorID);
    SELECT TOP (20) o.IndicatorID, o.Value, o.Status,
           (SELECT TOP (1) m.Name FROM dbo.MalwareIndicator AS mi JOIN dbo.Malware AS m ON m.MalwareID = mi.MalwareID
             WHERE mi.IndicatorID = o.IndicatorID) AS MalwareName
    FROM dbo.vw_IndicatorNetwork AS o
    WHERE o.IpNum BETWEEN @ip / 256 * 256 AND @ip / 256 * 256 + 255 AND o.IndicatorID <> @IndicatorID   -- IX_IndicatorNetwork_IpNum aralık araması
    ORDER BY o.IpNum;
END;
GO

-- Var olan IP IOC'leri için ilk hesap (aralık verisi yoksa yalnızca sayısal adres ve /24)
IF NOT EXISTS (SELECT 1 FROM dbo.IndicatorNetwork)
    EXEC dbo.sp_EnrichNetwork @All = 1, @Quiet = 1;
GO

GRANT EXECUTE ON dbo.sp_InfrastructureOverlap TO tip_reader;
GRANT EXECUTE ON dbo.sp_IndicatorNetwork TO tip_reader;
GRANT EXECUTE ON dbo.sp_LoadIpRanges TO tip_admin;
GO
