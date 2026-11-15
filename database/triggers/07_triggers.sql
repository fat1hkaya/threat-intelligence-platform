/* =====================================================================
   ThreatLens - 07: Tetikleyiciler
   Denetim izi uygulama koduna bırakılmaz; veriye hangi yoldan erişilirse
   erişilsin (arayüz, SSMS, betik) veritabanı kendisi kayıt tutar.
   Değişikliği yapan kullanıcı SESSION_CONTEXT('user_id') ile iletilir.
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

CREATE OR ALTER TRIGGER dbo.trg_Indicator_Audit
ON dbo.Indicator
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF TRY_CAST(SESSION_CONTEXT(N'skip_audit') AS INT) = 1 RETURN;   -- toplu içe aktarma
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;

    DECLARE @uid INT = TRY_CAST(SESSION_CONTEXT(N'user_id') AS INT);

    INSERT INTO dbo.AuditLog (TableName, RecordID, Action, ChangedBy, OldValues, NewValues)
    SELECT N'Indicator',
           COALESCE(i.IndicatorID, d.IndicatorID),
           CASE WHEN d.IndicatorID IS NULL THEN 'I' WHEN i.IndicatorID IS NULL THEN 'D' ELSE 'U' END,
           @uid,
           CASE WHEN d.IndicatorID IS NOT NULL THEN
               (SELECT d.NormalizedValue AS Value, d.Confidence, d.SeverityID, d.TLPID, d.SourceID, d.Status, d.ExpiresAt, d.Description
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END,
           CASE WHEN i.IndicatorID IS NOT NULL THEN
               (SELECT i.NormalizedValue AS Value, i.Confidence, i.SeverityID, i.TLPID, i.SourceID, i.Status, i.ExpiresAt, i.Description
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END
    FROM inserted AS i
    FULL OUTER JOIN deleted AS d ON d.IndicatorID = i.IndicatorID
    WHERE i.IndicatorID IS NULL OR d.IndicatorID IS NULL
       -- UPDATE'te yalnızca izlenen sütunlar gerçekten değiştiyse kayıt at (EXCEPT, NULL'ları da doğru karşılaştırır)
       OR EXISTS (SELECT i.NormalizedValue, i.Confidence, i.SeverityID, i.TLPID, i.SourceID, i.Status, i.ExpiresAt, i.Description
                  EXCEPT
                  SELECT d.NormalizedValue, d.Confidence, d.SeverityID, d.TLPID, d.SourceID, d.Status, d.ExpiresAt, d.Description);
END;
GO

CREATE OR ALTER TRIGGER dbo.trg_ThreatActor_Audit
ON dbo.ThreatActor
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF TRY_CAST(SESSION_CONTEXT(N'skip_audit') AS INT) = 1 RETURN;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;

    DECLARE @uid INT = TRY_CAST(SESSION_CONTEXT(N'user_id') AS INT);

    INSERT INTO dbo.AuditLog (TableName, RecordID, Action, ChangedBy, OldValues, NewValues)
    SELECT N'ThreatActor',
           COALESCE(i.ActorID, d.ActorID),
           CASE WHEN d.ActorID IS NULL THEN 'I' WHEN i.ActorID IS NULL THEN 'D' ELSE 'U' END,
           @uid,
           CASE WHEN d.ActorID IS NOT NULL THEN
               (SELECT d.Name, d.MotivationID, d.CountryCode, d.IsActive, d.Description FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END,
           CASE WHEN i.ActorID IS NOT NULL THEN
               (SELECT i.Name, i.MotivationID, i.CountryCode, i.IsActive, i.Description FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END
    FROM inserted AS i
    FULL OUTER JOIN deleted AS d ON d.ActorID = i.ActorID
    WHERE i.ActorID IS NULL OR d.ActorID IS NULL
       OR EXISTS (SELECT i.Name, i.MotivationID, i.CountryCode, i.IsActive, i.Description
                  EXCEPT
                  SELECT d.Name, d.MotivationID, d.CountryCode, d.IsActive, d.Description);
END;
GO

CREATE OR ALTER TRIGGER dbo.trg_Malware_Audit
ON dbo.Malware
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF TRY_CAST(SESSION_CONTEXT(N'skip_audit') AS INT) = 1 RETURN;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;

    DECLARE @uid INT = TRY_CAST(SESSION_CONTEXT(N'user_id') AS INT);

    INSERT INTO dbo.AuditLog (TableName, RecordID, Action, ChangedBy, OldValues, NewValues)
    SELECT N'Malware',
           COALESCE(i.MalwareID, d.MalwareID),
           CASE WHEN d.MalwareID IS NULL THEN 'I' WHEN i.MalwareID IS NULL THEN 'D' ELSE 'U' END,
           @uid,
           CASE WHEN d.MalwareID IS NOT NULL THEN
               (SELECT d.Name, d.MalwareTypeID, d.Platforms, d.Description FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END,
           CASE WHEN i.MalwareID IS NOT NULL THEN
               (SELECT i.Name, i.MalwareTypeID, i.Platforms, i.Description FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END
    FROM inserted AS i
    FULL OUTER JOIN deleted AS d ON d.MalwareID = i.MalwareID
    WHERE i.MalwareID IS NULL OR d.MalwareID IS NULL
       OR EXISTS (SELECT i.Name, i.MalwareTypeID, i.Platforms, i.Description
                  EXCEPT
                  SELECT d.Name, d.MalwareTypeID, d.Platforms, d.Description);
END;
GO

CREATE OR ALTER TRIGGER dbo.trg_Campaign_Audit
ON dbo.Campaign
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF TRY_CAST(SESSION_CONTEXT(N'skip_audit') AS INT) = 1 RETURN;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;

    DECLARE @uid INT = TRY_CAST(SESSION_CONTEXT(N'user_id') AS INT);

    INSERT INTO dbo.AuditLog (TableName, RecordID, Action, ChangedBy, OldValues, NewValues)
    SELECT N'Campaign',
           COALESCE(i.CampaignID, d.CampaignID),
           CASE WHEN d.CampaignID IS NULL THEN 'I' WHEN i.CampaignID IS NULL THEN 'D' ELSE 'U' END,
           @uid,
           CASE WHEN d.CampaignID IS NOT NULL THEN
               (SELECT d.Name, d.ActorID, d.StartDate, d.EndDate, d.Description FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END,
           CASE WHEN i.CampaignID IS NOT NULL THEN
               (SELECT i.Name, i.ActorID, i.StartDate, i.EndDate, i.Description FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END
    FROM inserted AS i
    FULL OUTER JOIN deleted AS d ON d.CampaignID = i.CampaignID
    WHERE i.CampaignID IS NULL OR d.CampaignID IS NULL
       OR EXISTS (SELECT i.Name, i.ActorID, i.StartDate, i.EndDate, i.Description
                  EXCEPT
                  SELECT d.Name, d.ActorID, d.StartDate, d.EndDate, d.Description);
END;
GO

/* Kullanıcı yönetimi de denetlenir (rol değişikliği, devre dışı bırakma). Parola özeti ASLA kayda yazılmaz. */
CREATE OR ALTER TRIGGER dbo.trg_AppUser_Audit
ON dbo.AppUser
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @uid INT = TRY_CAST(SESSION_CONTEXT(N'user_id') AS INT);

    INSERT INTO dbo.AuditLog (TableName, RecordID, Action, ChangedBy, OldValues, NewValues)
    SELECT N'AppUser',
           COALESCE(i.UserID, d.UserID),
           CASE WHEN d.UserID IS NULL THEN 'I' WHEN i.UserID IS NULL THEN 'D' ELSE 'U' END,
           @uid,
           CASE WHEN d.UserID IS NOT NULL THEN
               (SELECT d.Username, d.FullName, d.Email, d.RoleID, d.IsActive FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END,
           CASE WHEN i.UserID IS NOT NULL THEN
               (SELECT i.Username, i.FullName, i.Email, i.RoleID, i.IsActive FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END
    FROM inserted AS i
    FULL OUTER JOIN deleted AS d ON d.UserID = i.UserID
    WHERE i.UserID IS NULL OR d.UserID IS NULL
       -- LastLoginAt veya parola değişimi tek başına denetim kaydı üretmez
       OR EXISTS (SELECT i.Username, i.FullName, i.Email, i.RoleID, i.IsActive
                  EXCEPT
                  SELECT d.Username, d.FullName, d.Email, d.RoleID, d.IsActive);
END;
GO

/* ---------------------------------------------------------------------
   Görülme eklendiğinde göstergeyi tazele: LastSeen ilerler, süresi
   dolmuş gösterge yeniden etkinleşir. Çok satırlı INSERT'e uygundur
   (inserted tablosu küme olarak işlenir, satır satır değil).
   --------------------------------------------------------------------- */
CREATE OR ALTER TRIGGER dbo.trg_Sighting_AfterInsert
ON dbo.Sighting
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE i
    SET i.LastSeen  = CASE WHEN s.MaxSightedAt > i.LastSeen THEN s.MaxSightedAt ELSE i.LastSeen END,
        i.Status    = CASE WHEN i.Status = 'expired' THEN 'active' ELSE i.Status END,   -- iptal/yanlış pozitif kararına dokunmaz
        i.UpdatedAt = SYSUTCDATETIME()
    FROM dbo.Indicator AS i
    JOIN (SELECT IndicatorID, MAX(SightedAt) AS MaxSightedAt FROM inserted GROUP BY IndicatorID) AS s
      ON s.IndicatorID = i.IndicatorID;
END;
GO

/* Denetim kaydı değiştirilemez ve silinemez: INSTEAD OF tetikleyicisi işlemi reddeder */
CREATE OR ALTER TRIGGER dbo.trg_AuditLog_Protect
ON dbo.AuditLog
INSTEAD OF UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50020, N'Denetim kayıtları değiştirilemez veya silinemez.', 1;
END;
GO

/* Bir tekniğin alt tekniği, başka bir alt tekniğin altına bağlanamaz (hiyerarşi en çok iki düzey) */
CREATE OR ALTER TRIGGER dbo.trg_Technique_Hierarchy
ON dbo.Technique
AFTER INSERT, UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    IF NOT UPDATE(ParentTechniqueID) RETURN;

    IF EXISTS (SELECT 1
               FROM inserted AS i
               JOIN dbo.Technique AS p ON p.TechniqueID = i.ParentTechniqueID
               WHERE p.ParentTechniqueID IS NOT NULL)
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 50021, N'Alt teknik yalnızca bir üst tekniğe bağlanabilir.', 1;
    END;
END;
GO
