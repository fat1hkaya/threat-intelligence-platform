/* =====================================================================
   DEMO 6 - Eşzamanlılık: aynı kaydı iki oturum güncelliyor
   SSMS'te İKİ ayrı sorgu penceresi açın (iki ayrı oturum). Adımları sırayla çalıştırın.
   ===================================================================== */

/* ---------- Bölüm A: Kilitlenme ve yalıtım düzeyleri ---------- */

-- [Pencere 1] Adım 1: transaction başlat, güncelle, COMMIT etme
USE ThreatLens;
BEGIN TRANSACTION;
UPDATE dbo.Indicator SET Confidence = 11 WHERE IndicatorID = 1;
-- (bekleyin)

-- [Pencere 2] Adım 2: varsayılan READ COMMITTED -> sorgu BEKLER (Pencere 1 kilidi tutuyor)
USE ThreatLens;
SELECT IndicatorID, Confidence FROM dbo.Indicator WHERE IndicatorID = 1;

-- [Pencere 2] Adım 2b (alternatif): READ UNCOMMITTED -> beklemez ama KİRLİ OKUMA yapar (11 görünür)
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;
SELECT IndicatorID, Confidence FROM dbo.Indicator WHERE IndicatorID = 1;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;

-- [Pencere 1] Adım 3: geri al. Pencere 2'deki bekleyen sorgu eski değeri döndürür;
-- 2b'de okunan 11 değeri hiç kalıcı olmamış bir değerdi (kirli okuma).
ROLLBACK TRANSACTION;

-- Kim kimi bekliyor? (üçüncü bir pencerede, adım 2 beklerken)
SELECT session_id, blocking_session_id, wait_type, wait_time, DB_NAME(database_id) AS db
FROM sys.dm_exec_requests WHERE blocking_session_id <> 0;

/* ---------- Bölüm B: Kayıp güncelleme ve iyimser eşzamanlılık (rowversion) ---------- */
-- Uygulama bu yöntemi kullanır: IOC düzenleme formu açıldığında RowVer okunur,
-- kaydederken gönderilir. Arada başka biri kaydettiyse RowVer değişmiştir ve kayıt reddedilir.

-- [Pencere 1] ve [Pencere 2] Adım 1: ikisi de aynı RowVer'i okur
SELECT IndicatorID, Confidence, RowVer FROM dbo.vw_Indicator WHERE IndicatorID = 1;

-- [Pencere 1] Adım 2: okunan RowVer ile kaydet -> başarılı (RowVer değişir)
-- EXEC dbo.sp_SaveIndicator @IndicatorID = 1, ..., @Confidence = 60, @RowVer = '0x...okunan...';

-- [Pencere 2] Adım 3: ESKİ RowVer ile kaydet -> Hata 50009:
-- "Bu kayıt siz düzenlerken başka bir kullanıcı tarafından değiştirildi."
-- EXEC dbo.sp_SaveIndicator @IndicatorID = 1, ..., @Confidence = 90, @RowVer = '0x...aynı eski değer...';
-- Arayüzde: iki tarayıcı sekmesinde aynı IOC'nin düzenleme formunu açıp sırayla kaydedin.
