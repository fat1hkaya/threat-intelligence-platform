/* =====================================================================
   ThreatLens - 08: Yetkilendirme (DCL)
   Üç veritabanı rolü. Uygulamadaki roller (izleyici, analist, yönetici)
   ile birebir eşleşir; SSMS'ten doğrudan bağlanan kullanıcılar da
   aynı sınırlar içinde kalır.
   ===================================================================== */
USE ThreatLens;
GO

IF DATABASE_PRINCIPAL_ID(N'tip_reader') IS NULL  CREATE ROLE tip_reader;
IF DATABASE_PRINCIPAL_ID(N'tip_analyst') IS NULL CREATE ROLE tip_analyst;
IF DATABASE_PRINCIPAL_ID(N'tip_admin') IS NULL   CREATE ROLE tip_admin;
GO

/* İzleyici: yalnızca okur. Parola özetleri ve oturum anahtarları hariç. */
GRANT SELECT ON SCHEMA::dbo TO tip_reader;
DENY  SELECT ON dbo.UserSession TO tip_reader;
DENY  SELECT ON dbo.AppUser (PasswordHash) TO tip_reader;
GRANT EXECUTE ON dbo.sp_GlobalSearch    TO tip_reader;
GRANT EXECUTE ON dbo.sp_GetNeighborhood TO tip_reader;
GRANT EXECUTE ON dbo.sp_AttackMatrix    TO tip_reader;
GRANT EXECUTE ON dbo.sp_IndicatorKillChain  TO tip_reader;
GRANT EXECUTE ON dbo.sp_ActorShortestPath   TO tip_reader;
GRANT EXECUTE ON dbo.sp_CheckGraphConsistency TO tip_reader;
-- Graf tabloları ve MATCH görünümleri okunabilir (SCHEMA düzeyindeki SELECT bunları kapsar)
GO

/* Analist: izleyicinin tüm hakları + istihbarat verisini değiştirme */
ALTER ROLE tip_reader ADD MEMBER tip_analyst;
GRANT INSERT, UPDATE, DELETE ON dbo.Indicator         TO tip_analyst;
GRANT INSERT, UPDATE, DELETE ON dbo.ThreatActor       TO tip_analyst;
GRANT INSERT, UPDATE, DELETE ON dbo.ActorAlias        TO tip_analyst;
GRANT INSERT, UPDATE, DELETE ON dbo.Malware           TO tip_analyst;
GRANT INSERT, UPDATE, DELETE ON dbo.MalwareAlias      TO tip_analyst;
GRANT INSERT, UPDATE, DELETE ON dbo.Campaign          TO tip_analyst;
GRANT INSERT, UPDATE, DELETE ON dbo.Vulnerability     TO tip_analyst;
GRANT INSERT, DELETE ON dbo.IndicatorTag         TO tip_analyst;
GRANT INSERT, DELETE ON dbo.ActorMalware         TO tip_analyst;
GRANT INSERT, DELETE ON dbo.ActorTechnique       TO tip_analyst;
GRANT INSERT, DELETE ON dbo.ActorTargetSector    TO tip_analyst;
GRANT INSERT, DELETE ON dbo.ActorTargetCountry   TO tip_analyst;
GRANT INSERT, DELETE ON dbo.MalwareTechnique     TO tip_analyst;
GRANT INSERT, DELETE ON dbo.MalwareVulnerability TO tip_analyst;
GRANT INSERT, UPDATE, DELETE ON dbo.MalwareIndicator TO tip_analyst;
GRANT INSERT, DELETE ON dbo.CampaignMalware      TO tip_analyst;
GRANT INSERT, DELETE ON dbo.CampaignTechnique    TO tip_analyst;
GRANT INSERT, DELETE ON dbo.CampaignIndicator    TO tip_analyst;
GRANT INSERT ON dbo.Tag      TO tip_analyst;
GRANT INSERT ON dbo.Sighting TO tip_analyst;
GRANT INSERT, UPDATE ON dbo.Evidence TO tip_analyst;
-- Analist içe aktarma başlatabilir (şartname: Analyst = IOC yönetimi, ilişki ve import)
GRANT INSERT, UPDATE ON dbo.ImportJob      TO tip_analyst;
GRANT INSERT         ON dbo.ImportJobError TO tip_analyst;
GRANT EXECUTE ON dbo.sp_BulkImportIndicators TO tip_analyst;
GRANT EXECUTE ON dbo.sp_StartImportJob       TO tip_analyst;
GRANT EXECUTE ON dbo.sp_FinishImportJob      TO tip_analyst;
GRANT EXECUTE ON dbo.sp_RefreshActorSimilarity TO tip_analyst;
-- Graf tabloları: analist yazma işlemleri tetikleyicilerle grafa yansır. Tetikleyiciler tablo
-- sahibinin yetkisiyle çalıştığından (sahiplik zinciri) graf tablolarına doğrudan yazma yetkisi verilmez.
GRANT EXECUTE ON dbo.sp_SaveIndicator TO tip_analyst;
GRANT EXECUTE ON dbo.sp_AddSighting   TO tip_analyst;
GO

/* Yönetici: analistin hakları + kullanıcı, kaynak ve içe aktarma yönetimi */
ALTER ROLE tip_analyst ADD MEMBER tip_admin;
GRANT INSERT, UPDATE, DELETE ON dbo.AppUser TO tip_admin;
GRANT INSERT, UPDATE, DELETE ON dbo.Source  TO tip_admin;

GRANT EXECUTE ON SCHEMA::dbo TO tip_admin;
GO

/* Hiçbir rol denetim kaydını elle yazamaz/değiştiremez (yalnızca tetikleyiciler yazar) */
DENY INSERT, UPDATE, DELETE ON dbo.AuditLog TO tip_reader;
GO

/* Örnek: SQL Server oturumu açıp role bağlama (isteğe bağlı, sysadmin gerekir)
   CREATE LOGIN tl_analist WITH PASSWORD = N'<güçlü bir parola>';
   CREATE USER  tl_analist FOR LOGIN tl_analist;
   ALTER ROLE tip_analyst ADD MEMBER tl_analist;
   -- Yetkiyi geri alma:
   REVOKE DELETE ON dbo.Indicator FROM tip_analyst;

   Deneme: izleyici rolündeki bir kullanıcı adına çalıştır
   EXECUTE AS USER = 'tl_izleyici';
       DELETE FROM dbo.Indicator WHERE IndicatorID = 1;   -- Hata 229: DELETE izni reddedildi
   REVERT;
*/
