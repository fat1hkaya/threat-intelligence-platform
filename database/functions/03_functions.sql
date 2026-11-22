/* =====================================================================
   ThreatLens - 03: Fonksiyonlar
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---------------------------------------------------------------------
   Risk skoru: 0-100 (türetilmiş nitelik, saklanmaz, her okumada hesaplanır)
     taban puan = güven x 0,45 + önem ağırlığı x 0,35 + görülme sayısı x 2 (en çok 20)
     skor       = taban x kaynak güvenilirliği x tazelik x durum
   Formül tek yerde, satır içi tablo değerli fn_RiskBreakdown'dadır; bileşenleri ayrı ayrı döndürür
   (arayüzdeki "skor nasıl hesaplandı" dökümü). Satır içi olduğu için sorgu planına gömülür.
   "Şimdiki zaman" @AsOf parametresiyle verilir: fonksiyon içinde SYSUTCDATETIME() kullanmak skaler
   fonksiyonun satır içine alınmasını (scalar UDF inlining) engelliyordu ve sıralamayı yavaşlatıyordu.
   --------------------------------------------------------------------- */
CREATE OR ALTER FUNCTION dbo.fn_RiskBreakdown (
    @Confidence     TINYINT,
    @SeverityWeight TINYINT,
    @LastSeen       DATETIME2(0),
    @SightingCount  INT,
    @Reliability    CHAR(1),
    @IsActive       BIT,
    @AsOf           DATETIME2(0)
)
RETURNS TABLE
AS
RETURN
    SELECT p.ConfidencePart, p.SeverityPart, p.SightingPart, b.BasePoints,
           f.ReliabilityFactor, f.AgeDays, t.FreshnessFactor, f.StatusFactor,
           CAST(CASE WHEN r.Raw > 100 THEN 100 WHEN r.Raw < 0 THEN 0 ELSE ROUND(r.Raw, 0) END AS TINYINT) AS Score
    FROM (SELECT CAST(@Confidence * 0.45 AS DECIMAL(6,2)) AS ConfidencePart,
                 CAST(@SeverityWeight * 0.35 AS DECIMAL(6,2)) AS SeverityPart,
                 CAST(CASE WHEN ISNULL(@SightingCount, 0) > 10 THEN 20 ELSE ISNULL(@SightingCount, 0) * 2 END AS DECIMAL(6,2)) AS SightingPart) AS p
    CROSS APPLY (SELECT p.ConfidencePart + p.SeverityPart + p.SightingPart AS BasePoints) AS b
    CROSS APPLY (SELECT CAST(CASE @Reliability WHEN 'A' THEN 1.00 WHEN 'B' THEN 0.95 WHEN 'C' THEN 0.88
                                               WHEN 'D' THEN 0.78 WHEN 'E' THEN 0.68 ELSE 0.60 END AS DECIMAL(4,2)) AS ReliabilityFactor,
                        DATEDIFF(DAY, @LastSeen, @AsOf) AS AgeDays,
                        CAST(CASE WHEN @IsActive = 1 THEN 1.0 ELSE 0.5 END AS DECIMAL(3,1)) AS StatusFactor) AS f
    CROSS APPLY (SELECT CAST(CASE WHEN f.AgeDays <= 30 THEN 1.00 WHEN f.AgeDays <= 90 THEN 0.85
                                  WHEN f.AgeDays <= 180 THEN 0.65 ELSE 0.45 END AS DECIMAL(4,2)) AS FreshnessFactor) AS t
    CROSS APPLY (SELECT CAST(b.BasePoints * f.ReliabilityFactor * t.FreshnessFactor * f.StatusFactor AS DECIMAL(9,3)) AS Raw) AS r;
GO

/* Skaler sürüm: tek bir değer için (ör. SSMS'te veya başka bir yordamda) skor. Formül fn_RiskBreakdown'dan gelir. */
CREATE OR ALTER FUNCTION dbo.fn_RiskScore (
    @Confidence     TINYINT,
    @SeverityWeight TINYINT,
    @LastSeen       DATETIME2(0),
    @SightingCount  INT,
    @Reliability    CHAR(1),
    @IsActive       BIT,
    @AsOf           DATETIME2(0)
)
RETURNS TINYINT
AS
BEGIN
    RETURN (SELECT Score FROM dbo.fn_RiskBreakdown(@Confidence, @SeverityWeight, @LastSeen, @SightingCount, @Reliability, @IsActive, @AsOf));
END;
GO

/* Girilen değerin, seçilen gösterge tipine biçimce uyup uymadığını denetler (1 = uygun) */
CREATE OR ALTER FUNCTION dbo.fn_IsValidIndicator (@TypeCode VARCHAR(10), @Value NVARCHAR(400))
RETURNS BIT
AS
BEGIN
    DECLARE @ok BIT = 0;
    IF @Value IS NULL OR LEN(@Value) = 0 RETURN 0;

    IF @TypeCode = 'ipv4'
        SET @ok = CASE WHEN @Value NOT LIKE '%[^0-9.]%'
                        AND LEN(@Value) - LEN(REPLACE(@Value, '.', '')) = 3
                        AND @Value NOT LIKE '%..%' AND @Value NOT LIKE '.%' AND @Value NOT LIKE '%.'
                        AND TRY_CAST(PARSENAME(@Value, 4) AS INT) BETWEEN 0 AND 255
                        AND TRY_CAST(PARSENAME(@Value, 3) AS INT) BETWEEN 0 AND 255
                        AND TRY_CAST(PARSENAME(@Value, 2) AS INT) BETWEEN 0 AND 255
                        AND TRY_CAST(PARSENAME(@Value, 1) AS INT) BETWEEN 0 AND 255
                       THEN 1 ELSE 0 END;
    ELSE IF @TypeCode = 'ipv6'
        SET @ok = CASE WHEN @Value LIKE '%:%' AND @Value NOT LIKE '%[^0-9a-fA-F:.]%' THEN 1 ELSE 0 END;
    ELSE IF @TypeCode = 'domain'
        SET @ok = CASE WHEN @Value LIKE '%_._%' AND @Value NOT LIKE '%[^a-zA-Z0-9._-]%'
                        AND @Value NOT LIKE '%..%' AND @Value NOT LIKE '.%' AND @Value NOT LIKE '%.' THEN 1 ELSE 0 END;
    ELSE IF @TypeCode = 'url'
        SET @ok = CASE WHEN (@Value LIKE 'http://_%' OR @Value LIKE 'https://_%' OR @Value LIKE 'ftp://_%')
                        AND @Value NOT LIKE '% %' THEN 1 ELSE 0 END;
    ELSE IF @TypeCode = 'md5'
        SET @ok = CASE WHEN LEN(@Value) = 32 AND @Value NOT LIKE '%[^0-9a-fA-F]%' THEN 1 ELSE 0 END;
    ELSE IF @TypeCode = 'sha1'
        SET @ok = CASE WHEN LEN(@Value) = 40 AND @Value NOT LIKE '%[^0-9a-fA-F]%' THEN 1 ELSE 0 END;
    ELSE IF @TypeCode = 'sha256'
        SET @ok = CASE WHEN LEN(@Value) = 64 AND @Value NOT LIKE '%[^0-9a-fA-F]%' THEN 1 ELSE 0 END;
    ELSE IF @TypeCode = 'email'
        SET @ok = CASE WHEN @Value LIKE '%_@_%._%' AND @Value NOT LIKE '% %' THEN 1 ELSE 0 END;

    RETURN @ok;
END;
GO

/* Satır içi tablo değerli fonksiyon: bir aktörün kullandığı teknikler, taktikleriyle */
CREATE OR ALTER FUNCTION dbo.fn_ActorTechniques (@ActorID INT)
RETURNS TABLE
AS
RETURN
    SELECT t.TechniqueID, t.ExternalID, t.Name, ta.TacticID, ta.Name AS TacticName, ta.DisplayOrder
    FROM dbo.ActorTechnique AS atq
    JOIN dbo.Technique       AS t  ON t.TechniqueID = atq.TechniqueID
    JOIN dbo.TechniqueTactic AS tt ON tt.TechniqueID = t.TechniqueID
    JOIN dbo.Tactic          AS ta ON ta.TacticID = tt.TacticID
    WHERE atq.ActorID = @ActorID;
GO

/* Yer tutucu zararlı ailesi: kaynağın "aile bilinmiyor" anlamında verdiği adlar (ThreatFox "Unknown Loader",
   "Unknown Stealer" ...). ATT&CK kaydı olanlar hariç: "Unknown Logger" (S0130) gerçek bir araçtır.
   Malware.IsPlaceholder hesaplanmış sütunu bu fonksiyona bağlıdır (migrations/23): ALTER edilemez, yalnızca yoksa oluşturulur. */
IF OBJECT_ID(N'dbo.fn_IsPlaceholderMalware') IS NULL
    EXEC(N'CREATE FUNCTION dbo.fn_IsPlaceholderMalware (@Name NVARCHAR(100), @ExternalID VARCHAR(12))
RETURNS BIT WITH SCHEMABINDING
AS
BEGIN
    RETURN CASE WHEN @ExternalID IS NULL AND @Name LIKE N''Unknown%'' THEN 1 ELSE 0 END;
END;');
GO

/* Arayüzde gösterilecek aile adı: yer tutucular "Ailesi belirlenmemiş" olarak görünür (asıl ad kayıtta kalır) */
CREATE OR ALTER FUNCTION dbo.fn_MalwareLabel (@Name NVARCHAR(100), @ExternalID VARCHAR(12))
RETURNS NVARCHAR(100)
AS
BEGIN
    RETURN CASE WHEN dbo.fn_IsPlaceholderMalware(@Name, @ExternalID) = 1 THEN N'Ailesi belirlenmemiş' ELSE @Name END;
END;
GO
