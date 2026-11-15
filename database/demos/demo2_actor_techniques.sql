/* =====================================================================
   DEMO 2 - Bir tehdit aktörünün kullandığı MITRE ATT&CK teknikleri
   Arayüz: Tehdit Aktörleri -> APT29 -> "Kullandığı teknikler"; MITRE ATT&CK -> aktör filtresi.
   Beklenen: teknikler taktiklere göre gruplu; her ilişkinin ATT&CK kanıt metni var.
   ===================================================================== */
USE ThreatLens;
GO
DECLARE @actor INT = (SELECT ActorID FROM dbo.ThreatActor WHERE Name = N'APT29');

-- 1) Tablo değerli fonksiyon
SELECT TacticName, ExternalID, Name FROM dbo.fn_ActorTechniques(@actor) ORDER BY DisplayOrder, ExternalID;

-- 2) Taktik başına teknik sayısı (GROUP BY)
SELECT TacticName, COUNT(*) AS TeknikSayisi FROM dbo.fn_ActorTechniques(@actor) GROUP BY TacticName, DisplayOrder ORDER BY DisplayOrder;

-- 3) Aynı soru graf modelinde (MATCH) ve ilişkinin kanıtı
SELECT t.ExternalID, t.Name, ev.Summary AS Kanit, ev.Url
FROM (SELECT tn.TechniqueID, e.EvidenceID
      FROM dbo.ActorNode AS an, dbo.ActorUsesTechnique AS e, dbo.TechniqueNode AS tn
      WHERE MATCH(an-(e)->tn) AND an.ActorID = @actor) AS g
JOIN dbo.Technique AS t ON t.TechniqueID = g.TechniqueID
LEFT JOIN dbo.Evidence AS ev ON ev.EvidenceID = g.EvidenceID
ORDER BY t.ExternalID;

-- 4) ATT&CK matrisi yordamı (aktörün teknikleri işaretli)
EXEC dbo.sp_AttackMatrix @ActorID = @actor;
