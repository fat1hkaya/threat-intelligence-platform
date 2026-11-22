/* =====================================================================
   ThreatLens - 13: Kimlik doğrulama güvenliği
   Tekrar çalıştırılabilir.
   - LoginAttempt: her giriş denemesi (başarılı/başarısız) kaydedilir. Kaba kuvvete karşı:
     son 15 dakikada 5 başarısız deneme -> kullanıcı adı geçici olarak kilitlenir.
   - UserSession.Token artık oturum anahtarının SHA-256 özetidir (64 onaltılık karakter);
     ham anahtar yalnızca kullanıcının çerezinde durur. Veritabanı sızsa bile oturum çalınamaz.
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'dbo.LoginAttempt') IS NULL
BEGIN
    CREATE TABLE dbo.LoginAttempt (
        AttemptID   BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_LoginAttempt PRIMARY KEY,
        Username    NVARCHAR(50)  NOT NULL,                    -- yazılan ad (var olmayan kullanıcı da kaydedilir)
        UserID      INT NULL CONSTRAINT FK_LoginAttempt_AppUser REFERENCES dbo.AppUser(UserID) ON DELETE SET NULL,
        AttemptedAt DATETIME2(0)  NOT NULL CONSTRAINT DF_LoginAttempt_AttemptedAt DEFAULT (SYSUTCDATETIME()),
        Success     BIT           NOT NULL,
        ClientIP    VARCHAR(45)   NULL,
        Reason      VARCHAR(20)   NULL,                        -- bad_password, unknown_user, locked, inactive
        CONSTRAINT CK_LoginAttempt_Reason CHECK (Reason IS NULL OR Reason IN ('bad_password', 'unknown_user', 'locked', 'inactive'))
    );
    EXEC(N'CREATE INDEX IX_LoginAttempt_User_Time ON dbo.LoginAttempt (Username, AttemptedAt DESC) INCLUDE (Success);');
END;
GO

/* Kilit denetimi: son @WindowMinutes dakikadaki başarısız deneme sayısı ve kilidin açılacağı an */
CREATE OR ALTER FUNCTION dbo.fn_LoginLock (@Username NVARCHAR(50), @MaxFailures INT, @WindowMinutes INT)
RETURNS TABLE
AS
RETURN
    SELECT COUNT(*) AS RecentFailures,
           CASE WHEN COUNT(*) >= @MaxFailures THEN DATEADD(MINUTE, @WindowMinutes, MAX(AttemptedAt)) END AS LockedUntil
    FROM dbo.LoginAttempt
    WHERE Username = @Username AND Success = 0 AND Reason <> 'locked'
      AND AttemptedAt >= DATEADD(MINUTE, -@WindowMinutes, SYSUTCDATETIME())
      -- son başarılı girişten önceki hatalar sayılmaz
      AND AttemptedAt > ISNULL((SELECT MAX(s.AttemptedAt) FROM dbo.LoginAttempt AS s WHERE s.Username = @Username AND s.Success = 1), '19000101');
GO

/* Eski düz metin oturum anahtarları geçersiz: hepsi silinir (kullanıcılar bir kez yeniden giriş yapar) */
IF NOT EXISTS (SELECT 1 FROM sys.extended_properties WHERE major_id = OBJECT_ID(N'dbo.UserSession') AND name = N'TokenIsHash')
BEGIN
    DELETE FROM dbo.UserSession;
    EXEC sys.sp_addextendedproperty @name = N'TokenIsHash', @value = N'SHA-256 hex',
         @level0type = N'SCHEMA', @level0name = N'dbo', @level1type = N'TABLE', @level1name = N'UserSession';
END;
GO

/* Giriş denemeleri hassastır: tabloya hiçbir uygulama rolü doğrudan erişemez (tip_admin de tip_reader üyesi
   olduğundan DENY onu da kapsar). Yönetici yalnızca aşağıdaki yordamla okur: EXECUTE yetkisi tip_admin'dedir
   ve sahiplik zinciri sayesinde yordam içindeki SELECT tablo DENY'ına takılmaz. */
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.LoginAttempt TO tip_reader;
GO
CREATE OR ALTER PROCEDURE dbo.sp_LoginAttempts @Top INT = 50, @HideAutomation BIT = 1
AS
BEGIN
    SET NOCOUNT ON;
    -- Sahiplik zinciri: tablo DENY'ı yordam içinden okunurken denetlenmez; EXECUTE yetkisi yalnızca tip_admin'de
    -- Otomasyon: test istemcisi (IP 'testclient') ve pytest kullanıcı adları; @HideAutomation = 1 iken listelenmez
    SELECT TOP (@Top) a.AttemptID, a.Username, u.FullName, a.AttemptedAt, a.Success, a.ClientIP, a.Reason
    FROM dbo.LoginAttempt AS a LEFT JOIN dbo.AppUser AS u ON u.UserID = a.UserID
    WHERE @HideAutomation = 0 OR (ISNULL(a.ClientIP, '') <> 'testclient' AND a.Username NOT LIKE N'pytest-%')
    ORDER BY a.AttemptID DESC;
    SELECT COUNT(*) AS Total,
           SUM(CASE WHEN Success = 0 THEN 1 ELSE 0 END) AS Failed,
           SUM(CASE WHEN Success = 0 AND AttemptedAt >= DATEADD(HOUR, -24, SYSUTCDATETIME()) THEN 1 ELSE 0 END) AS Failed24h,
           SUM(CASE WHEN Reason = 'locked' THEN 1 ELSE 0 END) AS LockedAttempts
    FROM dbo.LoginAttempt
    WHERE @HideAutomation = 0 OR (ISNULL(ClientIP, '') <> 'testclient' AND Username NOT LIKE N'pytest-%');
END;
GO
