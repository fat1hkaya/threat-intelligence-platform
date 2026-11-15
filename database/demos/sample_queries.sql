/* =====================================================================
   ThreatLens - Örnek sorgular (rapor ve sunum için)
   Bu dosya kurulumda çalıştırılmaz. SSMS'te tek tek seçip çalıştırın.
   Her sorgu dersin bir konusunu gerçek bir analist sorusuyla gösterir.
   ===================================================================== */
USE ThreatLens;
GO

/* S1 - Temel SELECT + WHERE + ORDER BY
   Son 7 günde görülen, güveni 80 ve üzeri aktif göstergeler */
SELECT NormalizedValue, Confidence, LastSeen
FROM dbo.Indicator
WHERE Status = 'active' AND Confidence >= 80 AND LastSeen >= DATEADD(DAY, -7, SYSUTCDATETIME())
ORDER BY LastSeen DESC;

/* S2 - INNER JOIN (çoklu tablo)
   Her göstergenin tipi, önem düzeyi ve kaynağı */
SELECT i.NormalizedValue, t.Name AS Tip, s.Name AS Onem, src.Name AS Kaynak
FROM dbo.Indicator AS i
JOIN dbo.IndicatorType AS t   ON t.TypeID = i.TypeID
JOIN dbo.SeverityLevel AS s   ON s.SeverityID = i.SeverityID
JOIN dbo.Source        AS src ON src.SourceID = i.SourceID;

/* S3 - LEFT JOIN + IS NULL (anti-join)
   Hiçbir zararlıya veya kampanyaya bağlanmamış "sahipsiz" göstergeler */
SELECT i.IndicatorID, i.NormalizedValue
FROM dbo.Indicator AS i
LEFT JOIN dbo.MalwareIndicator  AS mi ON mi.IndicatorID = i.IndicatorID
LEFT JOIN dbo.CampaignIndicator AS ci ON ci.IndicatorID = i.IndicatorID
WHERE mi.IndicatorID IS NULL AND ci.IndicatorID IS NULL;

/* S4 - GROUP BY + HAVING + toplam fonksiyonları
   10'dan fazla zararlı yazılım kullanan aktörler */
SELECT a.Name, COUNT(*) AS ZararliSayisi
FROM dbo.ThreatActor AS a
JOIN dbo.ActorMalware AS am ON am.ActorID = a.ActorID
GROUP BY a.ActorID, a.Name
HAVING COUNT(*) > 10
ORDER BY ZararliSayisi DESC;

/* S5 - M:N ilişkide çift JOIN
   "Fidye yazılımı kullanan aktörler ve kullandıkları aileler" */
SELECT a.Name AS Aktor, m.Name AS FidyeYazilimi
FROM dbo.ThreatActor AS a
JOIN dbo.ActorMalware AS am ON am.ActorID = a.ActorID
JOIN dbo.Malware      AS m  ON m.MalwareID = am.MalwareID
JOIN dbo.MalwareType  AS mt ON mt.MalwareTypeID = m.MalwareTypeID
WHERE mt.Code = 'ransomware'
ORDER BY a.Name, m.Name;

/* S6 - Korelasyonlu alt sorgu + EXISTS
   Hem kimlik avı (T1566) hem PowerShell (T1059.001) kullanan aktörler */
SELECT a.Name
FROM dbo.ThreatActor AS a
WHERE EXISTS (SELECT 1 FROM dbo.ActorTechnique AS x JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
              WHERE x.ActorID = a.ActorID AND (t.ExternalID = 'T1566' OR t.ExternalID LIKE 'T1566.%'))
  AND EXISTS (SELECT 1 FROM dbo.ActorTechnique AS x JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
              WHERE x.ActorID = a.ActorID AND t.ExternalID = 'T1059.001');

/* S7 - Küme işlemleri: INTERSECT / EXCEPT
   APT28 ile APT29'un ortak teknikleri; sonra yalnızca APT28'e özgü olanlar */
SELECT t.ExternalID, t.Name FROM dbo.ActorTechnique AS x JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
JOIN dbo.ThreatActor AS a ON a.ActorID = x.ActorID WHERE a.Name = N'APT28'
INTERSECT
SELECT t.ExternalID, t.Name FROM dbo.ActorTechnique AS x JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
JOIN dbo.ThreatActor AS a ON a.ActorID = x.ActorID WHERE a.Name = N'APT29';

SELECT t.ExternalID, t.Name FROM dbo.ActorTechnique AS x JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
JOIN dbo.ThreatActor AS a ON a.ActorID = x.ActorID WHERE a.Name = N'APT28'
EXCEPT
SELECT t.ExternalID, t.Name FROM dbo.ActorTechnique AS x JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
JOIN dbo.ThreatActor AS a ON a.ActorID = x.ActorID WHERE a.Name = N'APT29';

/* S8 - İlişkisel bölme (division): "ilk erişim" taktiğindeki TÜM kök teknikleri kullanan aktör var mı?
   Çift NOT EXISTS kalıbı */
SELECT a.Name
FROM dbo.ThreatActor AS a
WHERE NOT EXISTS (
    SELECT 1
    FROM dbo.Technique AS t
    JOIN dbo.TechniqueTactic AS tt ON tt.TechniqueID = t.TechniqueID
    JOIN dbo.Tactic AS ta ON ta.TacticID = tt.TacticID
    WHERE ta.ShortName = 'initial-access' AND t.ParentTechniqueID IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM dbo.ActorTechnique AS x
          JOIN dbo.Technique AS c ON c.TechniqueID = x.TechniqueID
          WHERE x.ActorID = a.ActorID AND COALESCE(c.ParentTechniqueID, c.TechniqueID) = t.TechniqueID));

/* S9 - Self JOIN (özyinelemeli ilişki)
   Üst teknikler ve alt teknik sayıları */
SELECT p.ExternalID, p.Name, COUNT(c.TechniqueID) AS AltTeknikSayisi
FROM dbo.Technique AS p
LEFT JOIN dbo.Technique AS c ON c.ParentTechniqueID = p.TechniqueID
WHERE p.ParentTechniqueID IS NULL
GROUP BY p.TechniqueID, p.ExternalID, p.Name
ORDER BY AltTeknikSayisi DESC;

/* S10 - Pencere fonksiyonları: RANK + PARTITION BY
   Her motivasyon grubunda en çok teknik kullanan ilk 3 aktör */
WITH r AS (
    SELECT v.Motivation, v.Name, v.TechniqueCount,
           RANK() OVER (PARTITION BY v.Motivation ORDER BY v.TechniqueCount DESC) AS Sira
    FROM dbo.vw_ActorSummary AS v
)
SELECT Motivation, Sira, Name, TechniqueCount FROM r WHERE Sira <= 3 ORDER BY Motivation, Sira;

/* S11 - Pencere fonksiyonu: kümülatif toplam
   Günlük ilk kez görülen gösterge sayısı ve birikimli toplam */
SELECT d.Gun, d.Adet, SUM(d.Adet) OVER (ORDER BY d.Gun ROWS UNBOUNDED PRECEDING) AS Birikimli
FROM (SELECT CAST(FirstSeen AS DATE) AS Gun, COUNT(*) AS Adet FROM dbo.Indicator GROUP BY CAST(FirstSeen AS DATE)) AS d
ORDER BY d.Gun;

/* S12 - PIVOT: kaynak x gösterge tipi çapraz tablosu */
SELECT Kaynak, [ipv4], [domain], [url], [sha256], [md5]
FROM (SELECT s.Name AS Kaynak, t.Code AS Tip, i.IndicatorID
      FROM dbo.Indicator AS i
      JOIN dbo.Source AS s ON s.SourceID = i.SourceID
      JOIN dbo.IndicatorType AS t ON t.TypeID = i.TypeID) AS src
PIVOT (COUNT(IndicatorID) FOR Tip IN ([ipv4], [domain], [url], [sha256], [md5])) AS p
ORDER BY Kaynak;

/* S13 - Özyinelemeli CTE (ilişkisel yöntem): bir göstergeden aktöre giden yol.
   Aynı soru S20'de graf yöntemiyle (MATCH) sorulur; ikisini karşılaştırın.
   (IndicatorID'yi kendi verinize göre değiştirin) */
DECLARE @IndicatorID BIGINT = (SELECT TOP (1) IndicatorID FROM dbo.MalwareIndicator ORDER BY IndicatorID);
WITH yol AS (
    SELECT CAST('indicator' AS VARCHAR(15)) AS Tip, @IndicatorID AS ID, 0 AS Adim,
           CAST('indicator:' + CAST(@IndicatorID AS VARCHAR(20)) AS VARCHAR(400)) AS Iz
    UNION ALL
    SELECT CAST(e.SourceType AS VARCHAR(15)), e.SourceID, y.Adim + 1,
           CAST(y.Iz + ' <- ' + e.SourceType + ':' + CAST(e.SourceID AS VARCHAR(20)) AS VARCHAR(400))
    FROM yol AS y
    JOIN dbo.vw_GraphEdge AS e ON e.TargetType = y.Tip AND e.TargetID = y.ID
    WHERE y.Adim < 3 AND e.SourceType IN ('malware', 'campaign', 'actor')
)
SELECT Adim, Tip, ID, Iz FROM yol WHERE Tip = 'actor' OPTION (MAXRECURSION 10);

/* S14 - Görünüm + fonksiyon kullanımı: en riskli 20 gösterge */
SELECT TOP (20) Value, TypeName, RiskScore, Confidence, SeverityName, SourceName
FROM dbo.vw_Indicator
ORDER BY RiskScore DESC, LastSeen DESC;

/* S15 - UPDATE ... FROM (JOIN ile güncelleme)
   Güvenilirliği F olan kaynaktan gelen göstergelerin güvenini 20 puan düşür */
BEGIN TRANSACTION;
    UPDATE i
    SET i.Confidence = CASE WHEN i.Confidence >= 20 THEN i.Confidence - 20 ELSE 0 END
    FROM dbo.Indicator AS i
    JOIN dbo.Source AS s ON s.SourceID = i.SourceID
    WHERE s.Reliability = 'F';
ROLLBACK TRANSACTION;   -- örnek olduğu için geri alınır

/* S16 - Transaction + yalıtım düzeyi + iş kuralı ihlali (CHECK)
   Güven 0-100 dışında olamaz: hata alınır ve işlem geri sarılır */
BEGIN TRY
    BEGIN TRANSACTION;
        UPDATE dbo.Indicator SET Confidence = 150 WHERE IndicatorID = (SELECT MIN(IndicatorID) FROM dbo.Indicator);
    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    SELECT ERROR_NUMBER() AS HataNo, ERROR_MESSAGE() AS Mesaj;
END CATCH;

/* S17 - İndeksin etkisi: yürütme planını (Ctrl+M) açıp iki sorguyu karşılaştırın */
SET STATISTICS IO ON;
SELECT IndicatorID, NormalizedValue FROM dbo.Indicator WHERE NormalizedValue = N'198.51.100.23';                          -- IX_Indicator_NormalizedValue: Index Seek
SELECT IndicatorID, NormalizedValue FROM dbo.Indicator WITH (INDEX(PK_Indicator)) WHERE NormalizedValue = N'198.51.100.23'; -- zorla tarama: Clustered Index Scan
SET STATISTICS IO OFF;

/* S18 - Saklı yordam çağrıları */
EXEC dbo.sp_GlobalSearch @Query = N'lazarus';
EXEC dbo.sp_AttackMatrix @ActorID = NULL;
EXEC dbo.sp_ExpireIndicators;

/* ===================== SQL Graph sorguları ===================== */

/* S19 - MATCH, tek adım: APT28'in kullandığı zararlı yazılımlar */
SELECT m.Name
FROM dbo.ActorNode AS an, dbo.ActorUsesMalware AS e, dbo.MalwareNode AS mn, dbo.ThreatActor AS a, dbo.Malware AS m
WHERE MATCH(an-(e)->mn)
  AND a.ActorID = an.ActorID AND m.MalwareID = mn.MalwareID
  AND a.Name = N'APT28';

/* S20 - MATCH, çok adım ve ters yön: göstergeden aktöre ve aktörün tekniklerine
   gösterge -> zararlı <- aktör -> teknik  (S13'teki özyinelemeli CTE ile karşılaştırın) */
DECLARE @ioc BIGINT = (SELECT TOP (1) IndicatorID FROM dbo.MalwareIndicator ORDER BY IndicatorID);
SELECT DISTINCT m.Name AS Zararli, a.Name AS Aktor, t.ExternalID, t.Name AS Teknik
FROM dbo.IndicatorNode AS i_n, dbo.IndicatesMalware AS e1, dbo.MalwareNode AS m_n,
     dbo.ActorUsesMalware AS e2, dbo.ActorNode AS a_n, dbo.ActorUsesTechnique AS e3, dbo.TechniqueNode AS t_n,
     dbo.Malware AS m, dbo.ThreatActor AS a, dbo.Technique AS t
WHERE MATCH(i_n-(e1)->m_n<-(e2)-a_n-(e3)->t_n)
  AND i_n.IndicatorID = @ioc
  AND m.MalwareID = m_n.MalwareID AND a.ActorID = a_n.ActorID AND t.TechniqueID = t_n.TechniqueID;

/* S21 - MATCH ile örüntü: aynı tekniği kullanan, aynı zararlıyı paylaşan aktör çiftleri (üçgen) */
SELECT TOP (20) a1.Name AS Aktor1, a2.Name AS Aktor2, m.Name AS OrtakZararli
FROM dbo.ActorNode AS x1, dbo.ActorUsesMalware AS u1, dbo.MalwareNode AS mn, dbo.ActorUsesMalware AS u2, dbo.ActorNode AS x2,
     dbo.ThreatActor AS a1, dbo.ThreatActor AS a2, dbo.Malware AS m
WHERE MATCH(x1-(u1)->mn<-(u2)-x2)
  AND x1.ActorID < x2.ActorID
  AND a1.ActorID = x1.ActorID AND a2.ActorID = x2.ActorID AND m.MalwareID = mn.MalwareID
ORDER BY a1.Name;

/* S22 - SHORTEST_PATH: APT29'dan FIN7'ye, ortak araç zinciri üzerinden en kısa yol.
   Ağırlıksızdır (en az adım). Birden çok en kısa yol varsa biri döner. */
SELECT q.Yol, q.AdimSayisi
FROM (
    SELECT STRING_AGG(a2.ActorID, ' -> ') WITHIN GROUP (GRAPH PATH) AS Yol,
           LAST_VALUE(a2.ActorID) WITHIN GROUP (GRAPH PATH) AS Son,
           COUNT(a2.ActorID) WITHIN GROUP (GRAPH PATH) AS AdimSayisi
    FROM dbo.ActorNode AS a1, dbo.ActorSharesToolsWith FOR PATH AS s, dbo.ActorNode FOR PATH AS a2
    WHERE MATCH(SHORTEST_PATH(a1(-(s)->a2)+))
      AND a1.ActorID = (SELECT ActorID FROM dbo.ThreatActor WHERE Name = N'APT29')
) AS q
WHERE q.Son = (SELECT ActorID FROM dbo.ThreatActor WHERE Name = N'FIN7');
-- Uygulamadaki karşılığı (aktör adlarıyla):  EXEC dbo.sp_ActorShortestPath @FromActorID = ..., @ToActorID = ...;

/* S23 - İki model tutarlı mı? Her satırda Relational = Graph olmalı */
EXEC dbo.sp_CheckGraphConsistency;
