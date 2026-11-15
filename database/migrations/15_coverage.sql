/* =====================================================================
   ThreatLens - 15: Tespit kapsama haritası (detection coverage)
   Tekrar çalıştırılabilir.
   ---------------------------------------------------------------------
   Kurum, her ATT&CK tekniğini ne düzeyde tespit edebildiğini işaretler (0 yok, 1 kısmi, 2 tam).
   Alt teknik açıkça işaretlenmemişse üst tekniğin düzeyini devralır (fn_EffectiveCoverage).
   Sorular:
     - Bir aktörün tekniklerinin yüzde kaçını görebiliyoruz? Kör noktalar neler?   (sp_ActorCoverage)
     - En çok aktörün kullandığı ama tespit edemediğimiz teknikler?                 (sp_CoverageOverview)
     - TÜM tekniklerini tespit edebildiğimiz aktörler?   -> İLİŞKİSEL BÖLME (NOT EXISTS ... NOT EXISTS)
   Başlangıçta tablo boştur: kapsama kurumun kendi beyanıdır, uydurma veri yüklenmez.
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'dbo.DetectionCoverage') IS NULL
BEGIN
    CREATE TABLE dbo.DetectionCoverage (
        TechniqueID INT NOT NULL CONSTRAINT PK_DetectionCoverage PRIMARY KEY
                    CONSTRAINT FK_DetectionCoverage_Technique REFERENCES dbo.Technique(TechniqueID) ON DELETE CASCADE,
        Level       TINYINT       NOT NULL,                 -- 0 yok, 1 kısmi, 2 tam
        DataSource  NVARCHAR(100) NULL,                     -- ör. "Sysmon EID 1 + EDR"
        Note        NVARCHAR(400) NULL,
        UpdatedBy   INT NULL CONSTRAINT FK_DetectionCoverage_AppUser REFERENCES dbo.AppUser(UserID),
        UpdatedAt   DATETIME2(0)  NOT NULL CONSTRAINT DF_DetectionCoverage_UpdatedAt DEFAULT (SYSUTCDATETIME()),
        CONSTRAINT CK_DetectionCoverage_Level CHECK (Level BETWEEN 0 AND 2)
    );
END;
GO

/* Her tekniğin geçerli kapsama düzeyi: kendi kaydı, yoksa üst tekniğin kaydı, o da yoksa 0 */
CREATE OR ALTER FUNCTION dbo.fn_EffectiveCoverage ()
RETURNS TABLE
AS
RETURN
    SELECT t.TechniqueID,
           CAST(COALESCE(c.Level, pc.Level, 0) AS TINYINT) AS Level,
           CAST(CASE WHEN c.TechniqueID IS NULL AND pc.TechniqueID IS NOT NULL THEN 1 ELSE 0 END AS BIT) AS Inherited,
           COALESCE(c.DataSource, pc.DataSource) AS DataSource
    FROM dbo.Technique AS t
    LEFT JOIN dbo.DetectionCoverage AS c  ON c.TechniqueID = t.TechniqueID
    LEFT JOIN dbo.DetectionCoverage AS pc ON pc.TechniqueID = t.ParentTechniqueID;
GO

/* Bir aktörün teknikleri ve kapsama düzeyleri + özet (tam = 1, kısmi = 0,5 puan) */
CREATE OR ALTER PROCEDURE dbo.sp_ActorCoverage @ActorID INT
AS
BEGIN
    SET NOCOUNT ON;
    SELECT t.TechniqueID, t.ExternalID, t.Name, ec.Level, ec.Inherited, ec.DataSource,
           (SELECT STRING_AGG(ta.Name, ', ') WITHIN GROUP (ORDER BY ta.DisplayOrder) FROM dbo.TechniqueTactic AS tt
              JOIN dbo.Tactic AS ta ON ta.TacticID = tt.TacticID WHERE tt.TechniqueID = t.TechniqueID) AS Tactics,
           (SELECT COUNT(*) FROM dbo.ActorTechnique AS o WHERE o.TechniqueID = t.TechniqueID) AS ActorCount
    FROM dbo.ActorTechnique AS x
    JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
    JOIN dbo.fn_EffectiveCoverage() AS ec ON ec.TechniqueID = t.TechniqueID
    WHERE x.ActorID = @ActorID
    ORDER BY ec.Level, ActorCount DESC, t.ExternalID;

    SELECT COUNT(*) AS Techniques,
           SUM(CASE WHEN ec.Level = 2 THEN 1 ELSE 0 END) AS FullCount,
           SUM(CASE WHEN ec.Level = 1 THEN 1 ELSE 0 END) AS PartialCount,
           SUM(CASE WHEN ec.Level = 0 THEN 1 ELSE 0 END) AS NoneCount,
           CAST(100.0 * SUM(ec.Level) / NULLIF(2 * COUNT(*), 0) AS DECIMAL(5,1)) AS CoveragePct
    FROM dbo.ActorTechnique AS x
    JOIN dbo.fn_EffectiveCoverage() AS ec ON ec.TechniqueID = x.TechniqueID
    WHERE x.ActorID = @ActorID;
END;
GO

/* Genel görünüm: kör noktalar, taktik bazında kapsama, aktör sıralaması, ilişkisel bölme */
CREATE OR ALTER PROCEDURE dbo.sp_CoverageOverview
AS
BEGIN
    SET NOCOUNT ON;
    -- 1) Öncelikli kör noktalar: tespit edemediğimiz, en çok aktörün kullandığı teknikler
    SELECT TOP (15) t.TechniqueID, t.ExternalID, t.Name, COUNT(DISTINCT x.ActorID) AS ActorCount
    FROM dbo.ActorTechnique AS x
    JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
    JOIN dbo.fn_EffectiveCoverage() AS ec ON ec.TechniqueID = t.TechniqueID
    WHERE ec.Level = 0
    GROUP BY t.TechniqueID, t.ExternalID, t.Name
    ORDER BY ActorCount DESC, t.ExternalID;

    -- 2) Taktik bazında kapsama (üst teknikler)
    SELECT ta.TacticID, ta.Name, COUNT(*) AS Techniques,
           SUM(CASE WHEN ec.Level = 2 THEN 1 ELSE 0 END) AS FullCount,
           SUM(CASE WHEN ec.Level = 1 THEN 1 ELSE 0 END) AS PartialCount,
           CAST(100.0 * SUM(ec.Level) / NULLIF(2 * COUNT(*), 0) AS DECIMAL(5,1)) AS CoveragePct
    FROM dbo.Tactic AS ta
    JOIN dbo.TechniqueTactic AS tt ON tt.TacticID = ta.TacticID
    JOIN dbo.Technique AS t ON t.TechniqueID = tt.TechniqueID AND t.ParentTechniqueID IS NULL
    JOIN dbo.fn_EffectiveCoverage() AS ec ON ec.TechniqueID = t.TechniqueID
    GROUP BY ta.TacticID, ta.Name, ta.DisplayOrder
    ORDER BY ta.DisplayOrder;

    -- 3) Aktörler: kapsama yüzdesi (en az 10 tekniği olanlar), en kötüden iyiye
    SELECT TOP (12) a.ActorID, a.Name, COUNT(*) AS Techniques,
           CAST(100.0 * SUM(ec.Level) / NULLIF(2 * COUNT(*), 0) AS DECIMAL(5,1)) AS CoveragePct
    FROM dbo.ActorTechnique AS x
    JOIN dbo.ThreatActor AS a ON a.ActorID = x.ActorID
    JOIN dbo.fn_EffectiveCoverage() AS ec ON ec.TechniqueID = x.TechniqueID
    GROUP BY a.ActorID, a.Name
    HAVING COUNT(*) >= 10
    ORDER BY CoveragePct, Techniques DESC;

    -- 4) İLİŞKİSEL BÖLME: kullandığı TÜM teknikleri en az kısmi tespit edebildiğimiz aktörler.
    --    "Tespit edemediğimiz bir tekniği bulunmayan aktörler" (çift NOT EXISTS)
    SELECT a.ActorID, a.Name, (SELECT COUNT(*) FROM dbo.ActorTechnique AS q WHERE q.ActorID = a.ActorID) AS Techniques
    FROM dbo.ThreatActor AS a
    WHERE EXISTS (SELECT 1 FROM dbo.ActorTechnique AS x WHERE x.ActorID = a.ActorID)
      AND NOT EXISTS (
            SELECT 1 FROM dbo.ActorTechnique AS x
            WHERE x.ActorID = a.ActorID
              AND NOT EXISTS (SELECT 1 FROM dbo.fn_EffectiveCoverage() AS ec WHERE ec.TechniqueID = x.TechniqueID AND ec.Level > 0))
    ORDER BY Techniques DESC, a.Name;

    -- 5) Genel özet
    SELECT (SELECT COUNT(*) FROM dbo.DetectionCoverage) AS Marked,
           (SELECT COUNT(*) FROM dbo.Technique WHERE ParentTechniqueID IS NULL) AS TopTechniques,
           (SELECT COUNT(*) FROM dbo.Technique AS t JOIN dbo.fn_EffectiveCoverage() AS ec ON ec.TechniqueID = t.TechniqueID
             WHERE t.ParentTechniqueID IS NULL AND ec.Level = 2) AS FullTop,
           (SELECT COUNT(*) FROM dbo.Technique AS t JOIN dbo.fn_EffectiveCoverage() AS ec ON ec.TechniqueID = t.TechniqueID
             WHERE t.ParentTechniqueID IS NULL AND ec.Level = 1) AS PartialTop,
           (SELECT CAST(100.0 * SUM(ec.Level) / NULLIF(2 * COUNT(*), 0) AS DECIMAL(5,1))
              FROM (SELECT DISTINCT TechniqueID FROM dbo.ActorTechnique) AS u JOIN dbo.fn_EffectiveCoverage() AS ec ON ec.TechniqueID = u.TechniqueID) AS UsedCoveragePct;
END;
GO

/* Kapsama değişiklikleri de denetlenir */
CREATE OR ALTER TRIGGER dbo.trg_DetectionCoverage_Audit ON dbo.DetectionCoverage AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @uid INT = TRY_CAST(SESSION_CONTEXT(N'user_id') AS INT);
    INSERT INTO dbo.AuditLog (TableName, RecordID, Action, ChangedBy, OldValues, NewValues)
    SELECT N'DetectionCoverage', COALESCE(i.TechniqueID, d.TechniqueID),
           CASE WHEN d.TechniqueID IS NULL THEN 'I' WHEN i.TechniqueID IS NULL THEN 'D' ELSE 'U' END, @uid,
           CASE WHEN d.TechniqueID IS NOT NULL THEN (SELECT d.Level, d.DataSource, d.Note FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END,
           CASE WHEN i.TechniqueID IS NOT NULL THEN (SELECT i.Level, i.DataSource, i.Note FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END
    FROM inserted AS i FULL OUTER JOIN deleted AS d ON d.TechniqueID = i.TechniqueID
    WHERE i.TechniqueID IS NULL OR d.TechniqueID IS NULL
       OR EXISTS (SELECT i.Level, i.DataSource, i.Note EXCEPT SELECT d.Level, d.DataSource, d.Note);
END;
GO

GRANT INSERT, UPDATE, DELETE ON dbo.DetectionCoverage TO tip_analyst;
GRANT EXECUTE ON dbo.sp_ActorCoverage TO tip_reader;
GRANT EXECUTE ON dbo.sp_CoverageOverview TO tip_reader;
GO
