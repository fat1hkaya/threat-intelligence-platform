
    ) AS x
    ORDER BY x.Kind DESC, x.ObjectName;
END;
GO

/* ---------- 5. Graf sorgu yordamları ---------- */

/* Çok adımlı MATCH: bir göstergeden aktöre, aktörün kullandığı tekniklere kadar tek desen.
   gösterge -> zararlı <- aktör -> teknik */
CREATE OR ALTER PROCEDURE dbo.sp_IndicatorKillChain @IndicatorID BIGINT
AS
BEGIN
    SET NOCOUNT ON;
    SELECT m.Name AS Malware, a.Name AS Actor, t.ExternalID, t.Name AS Technique
    FROM dbo.IndicatorNode AS i_n, dbo.IndicatesMalware AS e1, dbo.MalwareNode AS m_n,
         dbo.ActorUsesMalware AS e2, dbo.ActorNode AS a_n,
         dbo.ActorUsesTechnique AS e3, dbo.TechniqueNode AS t_n,
         dbo.Malware AS m, dbo.ThreatActor AS a, dbo.Technique AS t
    WHERE MATCH(i_n-(e1)->m_n<-(e2)-a_n-(e3)->t_n)
      AND i_n.IndicatorID = @IndicatorID
      AND m.MalwareID = m_n.MalwareID AND a.ActorID = a_n.ActorID AND t.TechniqueID = t_n.TechniqueID
    ORDER BY a.Name, t.ExternalID;
END;
GO

/* SHORTEST_PATH: iki aktör arasındaki en kısa "ortak araç" zinciri.
   Ağırlıksız en kısa yoldur (adım sayısı en az olan); SharedCount yol ağırlığı olarak kullanılmaz.
   Birden çok en kısa yol varsa SQL Server bunlardan birini döndürür. */
CREATE OR ALTER PROCEDURE dbo.sp_ActorShortestPath
    @FromActorID INT,
    @ToActorID   INT,
    @MaxHops     TINYINT = 5
AS
BEGIN
    SET NOCOUNT ON;
    IF @FromActorID = @ToActorID THROW 50011, N'İki farklı aktör seçin.', 1;

    SELECT q.FromActorID, q.PathIDs, q.Hops
    FROM (
        SELECT a1.ActorID AS FromActorID,
               STRING_AGG(a2.ActorID, ',') WITHIN GROUP (GRAPH PATH) AS PathIDs,
               LAST_VALUE(a2.ActorID) WITHIN GROUP (GRAPH PATH) AS LastActorID,
               COUNT(a2.ActorID) WITHIN GROUP (GRAPH PATH) AS Hops
        FROM dbo.ActorNode AS a1,
             dbo.ActorSharesToolsWith FOR PATH AS s,
             dbo.ActorNode FOR PATH AS a2
        WHERE MATCH(SHORTEST_PATH(a1(-(s)->a2){1,6}))
          AND a1.ActorID = @FromActorID
    ) AS q
    WHERE q.LastActorID = @ToActorID AND q.Hops <= @MaxHops;
END;
GO


/* Türetilmiş aktör-aktör kenarını (en az 3 ortak yazılım) baştan hesaplar.
   Aktör-zararlı ilişkileri değişince (ATT&CK yüklemesi, arayüzden bağlama) çağrılır. */
CREATE OR ALTER PROCEDURE dbo.sp_RefreshActorSimilarity
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    BEGIN TRANSACTION;
    DELETE FROM dbo.ActorSharesToolsWith;
    INSERT INTO dbo.ActorSharesToolsWith ($from_id, $to_id, SharedCount)
    SELECT a.$node_id, b.$node_id, s.SharedCount
    FROM (
        SELECT x.ActorID AS FromActorID, y.ActorID AS ToActorID, COUNT(*) AS SharedCount
        FROM dbo.ActorMalware AS x
        JOIN dbo.ActorMalware AS y ON y.MalwareID = x.MalwareID AND y.ActorID <> x.ActorID   -- self join
        GROUP BY x.ActorID, y.ActorID
        HAVING COUNT(*) >= 3
    ) AS s
    JOIN dbo.ActorNode AS a ON a.ActorID = s.FromActorID
    JOIN dbo.ActorNode AS b ON b.ActorID = s.ToActorID;
    COMMIT TRANSACTION;
END;
GO
