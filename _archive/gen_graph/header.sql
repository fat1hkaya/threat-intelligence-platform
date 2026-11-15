/* =====================================================================
   ThreatLens - 05: SQL Server Graph katmanı (AS NODE / AS EDGE)
   ---------------------------------------------------------------------
   İlişkisel tablolar verinin asıl kaynağıdır (schema/01_tables.sql). Bu dosya aynı
   ilişkileri SQL Graph düğüm ve kenar tablolarına taşır; böylece çok adımlı
   sorular (gösterge -> zararlı -> aktör) MATCH ile, "iki aktör arasında kaç
   adım var" sorusu SHORTEST_PATH ile sorulabilir.

   Tasarım kararları
   - Düğüm tablosu yalnızca ilişkisel kaydın anahtarını taşır (UNIQUE). Ad,
     açıklama gibi nitelikler tekrar edilmez; vw_GraphNode ile birleştirilir.
   - Her kenar tablosunda kenar kısıtı (CONNECTION) vardır: yön ve uç tipleri
     veritabanında sabittir, yanlış tipte iki düğüm bağlanamaz.
   - ON DELETE CASCADE: düğüm silinince kenarları da silinir (sarkık kenar kalmaz).
   - Tutarlılık: her ilişkisel tabloda tetikleyici vardır. Kayıt veya ilişki eklenip
     silindiğinde düğüm/kenar AYNI transaction içinde güncellenir; işlem geri alınırsa
     graf değişikliği de geri alınır. sp_SyncGraph tüm grafı ilişkisel modelden yeniden
     kurar (ilk yükleme, onarım); sp_CheckGraphConsistency iki modeli karşılaştırır.
   Gereksinim: SQL Server 2019 veya üzeri (kenar kısıtı ve SHORTEST_PATH).
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

