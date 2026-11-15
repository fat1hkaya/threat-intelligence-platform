/* =====================================================================
   DEMO 7 - MATCH ile çok adımlı graf sorgusu ve SHORTEST_PATH
   Arayüz: İlişki Grafi -> "İki aktör arasındaki en kısa yol" (APT29 -> FIN7).
   ===================================================================== */
USE ThreatLens;
GO
-- 1) Üç adımlı desen: kampanya -> zararlı <- aktör -> teknik
--    "Bir kampanyada kullanılan zararlıyı başka hangi aktörler kullanıyor ve hangi tekniklerle?"
SELECT TOP (30) c.Name AS Kampanya, m.Name AS Zararli, a.Name AS Aktor, t.ExternalID
FROM dbo.CampaignNode AS cn, dbo.CampaignUsesMalware AS e1, dbo.MalwareNode AS mn,
     dbo.ActorUsesMalware AS e2, dbo.ActorNode AS an, dbo.ActorUsesTechnique AS e3, dbo.TechniqueNode AS tn,
     dbo.Campaign AS c, dbo.Malware AS m, dbo.ThreatActor AS a, dbo.Technique AS t
WHERE MATCH(cn-(e1)->mn<-(e2)-an-(e3)->tn)
  AND c.CampaignID = cn.CampaignID AND m.MalwareID = mn.MalwareID AND a.ActorID = an.ActorID AND t.TechniqueID = tn.TechniqueID
  AND t.ExternalID = 'T1059.001'
ORDER BY c.Name, a.Name;

-- 2) Aynı sorunun ilişkisel karşılığı: 6 JOIN. Okunabilirliği karşılaştırın.
SELECT TOP (30) c.Name, m.Name, a.Name, t.ExternalID
FROM dbo.Campaign AS c
JOIN dbo.CampaignMalware AS cm ON cm.CampaignID = c.CampaignID
JOIN dbo.Malware AS m ON m.MalwareID = cm.MalwareID
JOIN dbo.ActorMalware AS am ON am.MalwareID = m.MalwareID
JOIN dbo.ThreatActor AS a ON a.ActorID = am.ActorID
JOIN dbo.ActorTechnique AS at2 ON at2.ActorID = a.ActorID
JOIN dbo.Technique AS t ON t.TechniqueID = at2.TechniqueID
WHERE t.ExternalID = 'T1059.001'
ORDER BY c.Name, a.Name;

-- 3) SHORTEST_PATH (ağırlıksız, en az adım): APT29 -> FIN7
DECLARE @from INT = (SELECT ActorID FROM dbo.ThreatActor WHERE Name = N'APT29');
DECLARE @to   INT = (SELECT ActorID FROM dbo.ThreatActor WHERE Name = N'FIN7');
EXEC dbo.sp_ActorShortestPath @FromActorID = @from, @ToActorID = @to;

-- 4) Bir aktörden en çok 2 adımda ulaşılabilen tüm aktörler ve uzaklıkları
SELECT q.Hedef, a.Name, q.Adim
FROM (
    SELECT LAST_VALUE(a2.ActorID) WITHIN GROUP (GRAPH PATH) AS Hedef,
           COUNT(a2.ActorID) WITHIN GROUP (GRAPH PATH) AS Adim
    FROM dbo.ActorNode AS a1, dbo.ActorSharesToolsWith FOR PATH AS s, dbo.ActorNode FOR PATH AS a2
    WHERE MATCH(SHORTEST_PATH(a1(-(s)->a2){1,2}))
      AND a1.ActorID = @from
) AS q
JOIN dbo.ThreatActor AS a ON a.ActorID = q.Hedef
ORDER BY q.Adim, a.Name;
