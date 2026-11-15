/* =====================================================================
   DEMO 3 - Analist gösterge ekler, denetim kaydı oluşur
   Arayüz: "analist" kullanıcısıyla giriş -> IOC Araştırma -> "IOC ekle".
   Kayıt sonrası Denetim Kayıtları sayfasında "Oluşturuldu" satırı görünür;
   düzenleyince önceki ve yeni değerler yan yana gösterilir.
   SSMS'te aynı akış:
   ===================================================================== */
USE ThreatLens;
GO
DECLARE @analyst INT = (SELECT UserID FROM dbo.AppUser WHERE Username = N'analist');
DECLARE @src SMALLINT = (SELECT SourceID FROM dbo.Source WHERE Name = N'Analist girişi');

-- Tetikleyici, değişikliği yapanı oturum bağlamından okur (uygulama her istekte bunu ayarlar)
EXEC sys.sp_set_session_context @key = N'user_id', @value = @analyst;

-- 1) Ekle (normalleştirme uygulama katmanında yapılır; burada değer zaten kanonik)
EXEC dbo.sp_SaveIndicator @TypeCode = 'domain', @Value = N'Login-Verify[.]example', @NormalizedValue = N'login-verify.example',
     @Confidence = 80, @SeverityCode = 'high', @TLPCode = 'TLP:AMBER', @SourceID = @src,
     @Description = N'Demo 3: oltalama alan adı', @TagsJson = N'["phishing","demo"]', @UserID = @analyst;

DECLARE @id BIGINT = (SELECT IndicatorID FROM dbo.Indicator WHERE NormalizedValue = N'login-verify.example');

-- 2) Güncelle: güveni 80 -> 95
DECLARE @rv VARCHAR(18) = (SELECT RowVer FROM dbo.vw_Indicator WHERE IndicatorID = @id);
EXEC dbo.sp_SaveIndicator @IndicatorID = @id, @TypeCode = 'domain', @Value = N'Login-Verify[.]example', @NormalizedValue = N'login-verify.example',
     @Confidence = 95, @SeverityCode = 'high', @TLPCode = 'TLP:AMBER', @SourceID = @src, @RowVer = @rv, @UserID = @analyst;

-- 3) Denetim kaydı: kim, ne zaman, önce/sonra
SELECT l.Action, u.FullName, l.ChangedAt, l.OldValues, l.NewValues
FROM dbo.AuditLog AS l LEFT JOIN dbo.AppUser AS u ON u.UserID = l.ChangedBy
WHERE l.TableName = N'Indicator' AND l.RecordID = @id ORDER BY l.AuditID;

-- 4) Denetim kaydı değiştirilemez (INSTEAD OF tetikleyicisi): hata 50020 beklenir
BEGIN TRY
    DELETE FROM dbo.AuditLog WHERE RecordID = @id AND TableName = N'Indicator';
END TRY
BEGIN CATCH
    SELECT ERROR_NUMBER() AS HataNo, ERROR_MESSAGE() AS Mesaj;
END CATCH;

-- Temizlik (isteğe bağlı): DELETE FROM dbo.Indicator WHERE IndicatorID = @id;
