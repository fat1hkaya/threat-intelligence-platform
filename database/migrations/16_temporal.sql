/* =====================================================================
   ThreatLens - 16: Zaman yolculuğu (system-versioned temporal tables)
   Tekrar çalıştırılabilir.
   ---------------------------------------------------------------------
   Indicator ve MalwareIndicator tabloları sistem sürümlü tablolara dönüştürülür: bir satır her
   değiştiğinde veya silindiğinde eski hâli SQL Server tarafından otomatik olarak geçmiş tablosuna
   (IndicatorHistory, MalwareIndicatorHistory) yazılır. Uygulama kodu buna karışmaz.
     SELECT ... FROM dbo.Indicator FOR SYSTEM_TIME AS OF '2026-11-01'   -> o andaki hâl
     SELECT ... FROM dbo.Indicator FOR SYSTEM_TIME ALL WHERE ...         -> tüm sürümler
   Tetikleyiciyle tutulan AuditLog "kim, neyi" sorusunu, temporal tablolar "o anda veri neydi" sorusunu yanıtlar.
   Dönem sütunları HIDDEN'dır: SELECT * ve mevcut sorgular etkilenmez.
   Geçmiş, sürüm başlangıcından (bu betiğin ilk çalıştığı an) itibaren tutulur; 90 gün saklanır.
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECTPROPERTY(OBJECT_ID(N'dbo.Indicator'), 'TableTemporalType') = 0
BEGIN
    ALTER TABLE dbo.Indicator ADD
        ValidFrom DATETIME2(3) GENERATED ALWAYS AS ROW START HIDDEN NOT NULL
            CONSTRAINT DF_Indicator_ValidFrom DEFAULT (SYSUTCDATETIME()),
        ValidTo   DATETIME2(3) GENERATED ALWAYS AS ROW END HIDDEN NOT NULL
            CONSTRAINT DF_Indicator_ValidTo DEFAULT (CONVERT(DATETIME2(3), '9999-12-31 23:59:59.999')),
        PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo);
    ALTER TABLE dbo.Indicator SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.IndicatorHistory, HISTORY_RETENTION_PERIOD = 90 DAYS));
END;
GO

IF OBJECTPROPERTY(OBJECT_ID(N'dbo.MalwareIndicator'), 'TableTemporalType') = 0
BEGIN
    ALTER TABLE dbo.MalwareIndicator ADD
        ValidFrom DATETIME2(3) GENERATED ALWAYS AS ROW START HIDDEN NOT NULL
            CONSTRAINT DF_MalwareIndicator_ValidFrom DEFAULT (SYSUTCDATETIME()),
        ValidTo   DATETIME2(3) GENERATED ALWAYS AS ROW END HIDDEN NOT NULL
            CONSTRAINT DF_MalwareIndicator_ValidTo DEFAULT (CONVERT(DATETIME2(3), '9999-12-31 23:59:59.999')),
        PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo);
    ALTER TABLE dbo.MalwareIndicator SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.MalwareIndicatorHistory, HISTORY_RETENTION_PERIOD = 90 DAYS));
END;
GO

/* Bir IOC'nin tüm sürümleri (en yeniden eskiye) */
CREATE OR ALTER PROCEDURE dbo.sp_IndicatorVersions @IndicatorID BIGINT
AS
BEGIN
    SET NOCOUNT ON;
    SELECT i.ValidFrom, NULLIF(i.ValidTo, CONVERT(DATETIME2(3), '9999-12-31 23:59:59.999')) AS ValidTo,
           i.Status, i.Confidence, s.Code AS SeverityCode, i.LastSeen, i.ExpiresAt, i.Description,
           CAST(CASE WHEN i.ValidTo = CONVERT(DATETIME2(3), '9999-12-31 23:59:59.999') THEN 1 ELSE 0 END AS BIT) AS IsCurrent
    FROM dbo.Indicator FOR SYSTEM_TIME ALL AS i
    JOIN dbo.SeverityLevel AS s ON s.SeverityID = i.SeverityID
    WHERE i.IndicatorID = @IndicatorID
    ORDER BY i.ValidFrom DESC;
END;
GO

/* Bir IOC'nin belirli bir andaki hâli ve o andaki zararlı ilişkileri */
CREATE OR ALTER PROCEDURE dbo.sp_IndicatorAsOf @IndicatorID BIGINT, @AsOf DATETIME2(3)
AS
BEGIN
    SET NOCOUNT ON;
    SELECT i.IndicatorID, i.NormalizedValue AS Value, i.Status, i.Confidence, s.Code AS SeverityCode, i.LastSeen, i.ExpiresAt,
           i.ValidFrom, NULLIF(i.ValidTo, CONVERT(DATETIME2(3), '9999-12-31 23:59:59.999')) AS ValidTo
    FROM dbo.Indicator FOR SYSTEM_TIME AS OF @AsOf AS i
    JOIN dbo.SeverityLevel AS s ON s.SeverityID = i.SeverityID
    WHERE i.IndicatorID = @IndicatorID;

    SELECT mi.MalwareID, m.Name AS MalwareName, mi.Role, mi.Confidence
    FROM dbo.MalwareIndicator FOR SYSTEM_TIME AS OF @AsOf AS mi
    JOIN dbo.Malware AS m ON m.MalwareID = mi.MalwareID
    WHERE mi.IndicatorID = @IndicatorID;
END;
GO

/* Platform geneli: belirli bir anda durum dağılımı (sürüm tutulmaya başlandıktan sonrası için anlamlıdır) */
CREATE OR ALTER PROCEDURE dbo.sp_IndicatorStatsAsOf @AsOf DATETIME2(3)
AS
BEGIN
    SET NOCOUNT ON;
    SELECT i.Status, COUNT(*) AS Total
    FROM dbo.Indicator FOR SYSTEM_TIME AS OF @AsOf AS i
    GROUP BY i.Status;
    SELECT MIN(ValidFrom) AS TrackingSince FROM dbo.Indicator FOR SYSTEM_TIME ALL;
END;
GO

GRANT EXECUTE ON dbo.sp_IndicatorVersions TO tip_reader;
GRANT EXECUTE ON dbo.sp_IndicatorAsOf TO tip_reader;
GRANT EXECUTE ON dbo.sp_IndicatorStatsAsOf TO tip_reader;
GO
