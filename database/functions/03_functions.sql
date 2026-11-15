/* =====================================================================
   ThreatLens - 03: Fonksiyonlar
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---------------------------------------------------------------------
   fn_RiskScore: 0-100 arası risk skoru (türetilmiş nitelik, saklanmaz)
     güven        x 0.45
   + önem ağırlığı x 0.35
   + görülme sayısı x 2 (en çok 20 puan)
   sonra kaynak güvenilirliği ve tazelik (son görülme) ile çarpılır.
   --------------------------------------------------------------------- */
CREATE OR ALTER FUNCTION dbo.fn_RiskScore (
    @Confidence     TINYINT,
    @SeverityWeight TINYINT,
    @LastSeen       DATETIME2(0),
    @SightingCount  INT,
    @Reliability    CHAR(1),
    @IsActive       BIT
)
RETURNS TINYINT
AS
BEGIN
    DECLARE @base DECIMAL(9,3) =
          @Confidence * 0.45
        + @SeverityWeight * 0.35
        + CASE WHEN ISNULL(@SightingCount, 0) > 10 THEN 20 ELSE ISNULL(@SightingCount, 0) * 2 END;

    DECLARE @rel DECIMAL(4,2) = CASE @Reliability
        WHEN 'A' THEN 1.00 WHEN 'B' THEN 0.95 WHEN 'C' THEN 0.88
        WHEN 'D' THEN 0.78 WHEN 'E' THEN 0.68 ELSE 0.60 END;

    DECLARE @days INT = DATEDIFF(DAY, @LastSeen, SYSUTCDATETIME());
    DECLARE @fresh DECIMAL(4,2) = CASE
        WHEN @days <= 30  THEN 1.00
        WHEN @days <= 90  THEN 0.85
        WHEN @days <= 180 THEN 0.65
        ELSE 0.45 END;

    DECLARE @score DECIMAL(9,3) = @base * @rel * @fresh * CASE WHEN @IsActive = 1 THEN 1.0 ELSE 0.5 END;
    RETURN CAST(CASE WHEN @score > 100 THEN 100 WHEN @score < 0 THEN 0 ELSE ROUND(@score, 0) END AS TINYINT);
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

