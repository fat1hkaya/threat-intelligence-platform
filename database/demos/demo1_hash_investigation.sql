/* =====================================================================
   DEMO 1 - SHA-256 özetinden tehdit araştırması
   Senaryo: SOC'a şüpheli bir dosyanın SHA-256 özeti geliyor.
   Arayüz: üst arama kutusuna özeti yapıştırın -> IOC detayı -> "Grafikte aç".
   Beklenen: özet bir zararlı yazılım ailesine bağlı; aile bir veya birkaç
   aktöre, aktör de ATT&CK tekniklerine bağlı.
   ===================================================================== */
USE ThreatLens;
GO
-- 1) Örnek bir SHA-256 seç (demo verisinden; kendi değerinizi de yazabilirsiniz)
DECLARE @hash NVARCHAR(400) = (
    SELECT TOP (1) i.NormalizedValue
    FROM dbo.Indicator AS i
    JOIN dbo.IndicatorType AS t ON t.TypeID = i.TypeID AND t.Code = 'sha256'
    JOIN dbo.MalwareIndicator AS mi ON mi.IndicatorID = i.IndicatorID
    JOIN dbo.ActorMalware AS am ON am.MalwareID = mi.MalwareID
    ORDER BY i.IndicatorID);
SELECT @hash AS ArastirilanOzet;

-- 2) Gösterge kaydı ve risk skoru (görünüm + skaler fonksiyon)
SELECT Value, TypeName, RiskScore, Confidence, SeverityName, SourceName, Status, FirstSeen, LastSeen
FROM dbo.vw_Indicator WHERE Value = @hash;

-- 3) Atıf zinciri (MATCH tabanlı görünüm): özet -> zararlı -> aktör
SELECT a.ViaType, a.ViaName, a.Role, a.ActorName, ev.Summary AS Kanit
FROM dbo.vw_IndicatorAttribution AS a
JOIN dbo.Indicator AS i ON i.IndicatorID = a.IndicatorID
LEFT JOIN dbo.Evidence AS ev ON ev.EvidenceID = a.EvidenceID
WHERE i.NormalizedValue = @hash;

-- 4) Çok adımlı MATCH: özet -> zararlı <- aktör -> teknik
DECLARE @id BIGINT = (SELECT IndicatorID FROM dbo.Indicator WHERE NormalizedValue = @hash);
EXEC dbo.sp_IndicatorKillChain @IndicatorID = @id;

-- 5) İlişki grafı ekranının çağırdığı yordam (2 adım)
EXEC dbo.sp_GetNeighborhood @NodeType = 'indicator', @NodeID = @id, @Depth = 2;
