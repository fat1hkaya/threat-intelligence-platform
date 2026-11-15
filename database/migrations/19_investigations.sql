/* =====================================================================
   ThreatLens - 19: Vaka (soruşturma) çalışma alanı
   Tekrar çalıştırılabilir.
   ---------------------------------------------------------------------
   Investigation      : vaka (başlık, durum, önem, sorumlu)
   InvestigationNote  : not / zaman çizelgesi (1:N)
   InvestigationNode  : vakanın graf düğümü (AS NODE)
   InvestigationIncludes (AS EDGE): vakaya eklenen varlıklar.
     Tasarım kararı: vakaya 6 farklı türde varlık (IOC, zararlı, aktör, kampanya, teknik, zafiyet) bağlanır.
     İlişkisel çözüm ya 6 ayrı ara tablo ya da yabancı anahtarı OLMAYAN tek bir "çok biçimli" tablo
     (EntityType + EntityID) gerektirirdi; ikincisi bütünlük denetimini kaybettiren bilinen bir anti-desendir.
     SQL Graph kenar kısıtı tek tabloda birden çok bağlantı türüne izin verir ve her birini tür güvenli
     yapar: CONNECTION (InvestigationNode TO IndicatorNode, InvestigationNode TO MalwareNode, ...).
     Bağlanan varlık silinirse ON DELETE CASCADE kenarı da siler (sarkık kayıt kalmaz).
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'dbo.Investigation') IS NULL
BEGIN
    CREATE TABLE dbo.Investigation (
        InvestigationID INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Investigation PRIMARY KEY,
        Title       NVARCHAR(150)  NOT NULL,
        Summary     NVARCHAR(2000) NULL,
        Status      VARCHAR(15)    NOT NULL CONSTRAINT DF_Investigation_Status DEFAULT ('open'),
        SeverityID  TINYINT        NOT NULL CONSTRAINT FK_Investigation_SeverityLevel REFERENCES dbo.SeverityLevel(SeverityID),
        CreatedBy   INT NULL CONSTRAINT FK_Investigation_Creator REFERENCES dbo.AppUser(UserID),
        AssignedTo  INT NULL CONSTRAINT FK_Investigation_Assignee REFERENCES dbo.AppUser(UserID),
        CreatedAt   DATETIME2(0)   NOT NULL CONSTRAINT DF_Investigation_CreatedAt DEFAULT (SYSUTCDATETIME()),
        UpdatedAt   DATETIME2(0)   NOT NULL CONSTRAINT DF_Investigation_UpdatedAt DEFAULT (SYSUTCDATETIME()),
        ClosedAt    DATETIME2(0)   NULL,
        CONSTRAINT CK_Investigation_Status CHECK (Status IN ('open', 'investigating', 'closed')),
        CONSTRAINT CK_Investigation_Closed CHECK ((Status = 'closed' AND ClosedAt IS NOT NULL) OR (Status <> 'closed' AND ClosedAt IS NULL)),
        CONSTRAINT CK_Investigation_Title CHECK (LEN(Title) >= 3)
    );
    EXEC(N'CREATE INDEX IX_Investigation_Status ON dbo.Investigation (Status, UpdatedAt DESC);');
END;
GO
IF OBJECT_ID(N'dbo.InvestigationNote') IS NULL
BEGIN
    CREATE TABLE dbo.InvestigationNote (
        NoteID          INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_InvestigationNote PRIMARY KEY,
        InvestigationID INT NOT NULL CONSTRAINT FK_InvestigationNote_Investigation REFERENCES dbo.Investigation(InvestigationID) ON DELETE CASCADE,
        AuthorID        INT NULL CONSTRAINT FK_InvestigationNote_AppUser REFERENCES dbo.AppUser(UserID),
        CreatedAt       DATETIME2(0)   NOT NULL CONSTRAINT DF_InvestigationNote_CreatedAt DEFAULT (SYSUTCDATETIME()),
        Body            NVARCHAR(2000) NOT NULL,
        CONSTRAINT CK_InvestigationNote_Body CHECK (LEN(Body) > 0)
    );
    EXEC(N'CREATE INDEX IX_InvestigationNote_Inv ON dbo.InvestigationNote (InvestigationID, CreatedAt DESC);');
END;
GO
IF OBJECT_ID(N'dbo.InvestigationNode') IS NULL
    CREATE TABLE dbo.InvestigationNode (
        InvestigationID INT NOT NULL CONSTRAINT UQ_InvestigationNode_InvestigationID UNIQUE
    ) AS NODE;
GO
IF OBJECT_ID(N'dbo.InvestigationIncludes') IS NULL
BEGIN
    CREATE TABLE dbo.InvestigationIncludes (
        AddedBy INT NULL,
        AddedAt DATETIME2(0) NOT NULL CONSTRAINT DF_InvestigationIncludes_AddedAt DEFAULT (SYSUTCDATETIME()),
        Note    NVARCHAR(400) NULL,
        CONSTRAINT EC_InvestigationIncludes CONNECTION (
            dbo.InvestigationNode TO dbo.IndicatorNode,
            dbo.InvestigationNode TO dbo.MalwareNode,
            dbo.InvestigationNode TO dbo.ActorNode,
            dbo.InvestigationNode TO dbo.CampaignNode,
            dbo.InvestigationNode TO dbo.TechniqueNode,
            dbo.InvestigationNode TO dbo.VulnerabilityNode) ON DELETE CASCADE
    ) AS EDGE;
    EXEC(N'CREATE UNIQUE INDEX UX_InvestigationIncludes_FromTo ON dbo.InvestigationIncludes ($from_id, $to_id);');
    EXEC(N'CREATE INDEX IX_InvestigationIncludes_To ON dbo.InvestigationIncludes ($to_id);');
END;
GO

/* Vaka eklenince/silinince graf düğümü aynı transaction'da */
CREATE OR ALTER TRIGGER dbo.trg_Investigation_GraphNode ON dbo.Investigation AFTER INSERT, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DELETE n FROM dbo.InvestigationNode AS n JOIN deleted AS d ON d.InvestigationID = n.InvestigationID;
    INSERT INTO dbo.InvestigationNode (InvestigationID) SELECT i.InvestigationID FROM inserted AS i
    WHERE NOT EXISTS (SELECT 1 FROM dbo.InvestigationNode AS n WHERE n.InvestigationID = i.InvestigationID);
END;
GO
/* Durum değişiklikleri denetlenir */
CREATE OR ALTER TRIGGER dbo.trg_Investigation_Audit ON dbo.Investigation AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM inserted) AND NOT EXISTS (SELECT 1 FROM deleted) RETURN;
    DECLARE @uid INT = TRY_CAST(SESSION_CONTEXT(N'user_id') AS INT);
    INSERT INTO dbo.AuditLog (TableName, RecordID, Action, ChangedBy, OldValues, NewValues)
    SELECT N'Investigation', COALESCE(i.InvestigationID, d.InvestigationID),
           CASE WHEN d.InvestigationID IS NULL THEN 'I' WHEN i.InvestigationID IS NULL THEN 'D' ELSE 'U' END, @uid,
           CASE WHEN d.InvestigationID IS NOT NULL THEN (SELECT d.Title, d.Status, d.SeverityID, d.AssignedTo FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END,
           CASE WHEN i.InvestigationID IS NOT NULL THEN (SELECT i.Title, i.Status, i.SeverityID, i.AssignedTo FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END
    FROM inserted AS i FULL OUTER JOIN deleted AS d ON d.InvestigationID = i.InvestigationID
    WHERE i.InvestigationID IS NULL OR d.InvestigationID IS NULL
       OR EXISTS (SELECT i.Title, i.Status, i.SeverityID, i.AssignedTo EXCEPT SELECT d.Title, d.Status, d.SeverityID, d.AssignedTo);
END;
GO

/* Vakadaki varlıklar: kenar hangi düğüm tablosuna gidiyorsa o tür (MATCH, düğüm türü başına) */
CREATE OR ALTER VIEW dbo.vw_InvestigationItem
AS
SELECT v.InvestigationID, 'indicator' AS NodeType, CAST(t.IndicatorID AS BIGINT) AS NodeID, e.AddedBy, e.AddedAt, e.Note
FROM dbo.InvestigationNode AS v, dbo.InvestigationIncludes AS e, dbo.IndicatorNode AS t WHERE MATCH(v-(e)->t)
UNION ALL
SELECT v.InvestigationID, 'malware', t.MalwareID, e.AddedBy, e.AddedAt, e.Note
FROM dbo.InvestigationNode AS v, dbo.InvestigationIncludes AS e, dbo.MalwareNode AS t WHERE MATCH(v-(e)->t)
UNION ALL
SELECT v.InvestigationID, 'actor', t.ActorID, e.AddedBy, e.AddedAt, e.Note
FROM dbo.InvestigationNode AS v, dbo.InvestigationIncludes AS e, dbo.ActorNode AS t WHERE MATCH(v-(e)->t)
UNION ALL
SELECT v.InvestigationID, 'campaign', t.CampaignID, e.AddedBy, e.AddedAt, e.Note
FROM dbo.InvestigationNode AS v, dbo.InvestigationIncludes AS e, dbo.CampaignNode AS t WHERE MATCH(v-(e)->t)
UNION ALL
SELECT v.InvestigationID, 'technique', t.TechniqueID, e.AddedBy, e.AddedAt, e.Note
FROM dbo.InvestigationNode AS v, dbo.InvestigationIncludes AS e, dbo.TechniqueNode AS t WHERE MATCH(v-(e)->t)
UNION ALL
SELECT v.InvestigationID, 'vulnerability', t.VulnerabilityID, e.AddedBy, e.AddedAt, e.Note
FROM dbo.InvestigationNode AS v, dbo.InvestigationIncludes AS e, dbo.VulnerabilityNode AS t WHERE MATCH(v-(e)->t);
GO

/* Vakaya varlık ekler. Düğüm türü izinli listeden seçilir; kenar kısıtı yanlış türü zaten reddeder. */
CREATE OR ALTER PROCEDURE dbo.sp_InvestigationAddItem
    @InvestigationID INT, @NodeType VARCHAR(15), @NodeID BIGINT, @Note NVARCHAR(400) = NULL, @UserID INT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @from NVARCHAR(1000) = (SELECT $node_id FROM dbo.InvestigationNode WHERE InvestigationID = @InvestigationID);
    IF @from IS NULL THROW 50060, N'Vaka bulunamadı.', 1;
    IF EXISTS (SELECT 1 FROM dbo.Investigation WHERE InvestigationID = @InvestigationID AND Status = 'closed')
        THROW 50064, N'Kapalı vakaya kayıt eklenemez; önce vakayı yeniden açın.', 1;
    DECLARE @to NVARCHAR(1000) = CASE @NodeType
        WHEN 'indicator'     THEN (SELECT $node_id FROM dbo.IndicatorNode     WHERE IndicatorID = @NodeID)
        WHEN 'malware'       THEN (SELECT $node_id FROM dbo.MalwareNode       WHERE MalwareID = @NodeID)
        WHEN 'actor'         THEN (SELECT $node_id FROM dbo.ActorNode         WHERE ActorID = @NodeID)
        WHEN 'campaign'      THEN (SELECT $node_id FROM dbo.CampaignNode      WHERE CampaignID = @NodeID)
        WHEN 'technique'     THEN (SELECT $node_id FROM dbo.TechniqueNode     WHERE TechniqueID = @NodeID)
        WHEN 'vulnerability' THEN (SELECT $node_id FROM dbo.VulnerabilityNode WHERE VulnerabilityID = @NodeID) END;
    IF @to IS NULL THROW 50061, N'Eklenecek kayıt bulunamadı.', 1;
    IF EXISTS (SELECT 1 FROM dbo.InvestigationIncludes WHERE $from_id = @from AND $to_id = @to)
        THROW 50062, N'Bu kayıt vakada zaten var.', 1;
    INSERT INTO dbo.InvestigationIncludes ($from_id, $to_id, AddedBy, Note) VALUES (@from, @to, @UserID, @Note);
    UPDATE dbo.Investigation SET UpdatedAt = SYSUTCDATETIME() WHERE InvestigationID = @InvestigationID;
END;
GO

CREATE OR ALTER PROCEDURE dbo.sp_InvestigationRemoveItem @InvestigationID INT, @NodeType VARCHAR(15), @NodeID BIGINT
AS
BEGIN
    SET NOCOUNT ON;
    -- Uç düğümlerin kimlikleri önce değişkene alınır, kenar $from_id/$to_id eşitliğiyle silinir.
    -- (Alt sorgulu CASE'i doğrudan $to_id ile karşılaştırmak, iç sorgudaki $node_id dış sorgudaki
    --  düğüm tablosuna bağlandığından eşleşmiyordu; değişkenle bu belirsizlik ortadan kalkar.)
    DECLARE @from NVARCHAR(1000) = (SELECT $node_id FROM dbo.InvestigationNode WHERE InvestigationID = @InvestigationID);
    DECLARE @to NVARCHAR(1000) = CASE @NodeType
        WHEN 'indicator'     THEN (SELECT $node_id FROM dbo.IndicatorNode     WHERE IndicatorID = @NodeID)
        WHEN 'malware'       THEN (SELECT $node_id FROM dbo.MalwareNode       WHERE MalwareID = @NodeID)
        WHEN 'actor'         THEN (SELECT $node_id FROM dbo.ActorNode         WHERE ActorID = @NodeID)
        WHEN 'campaign'      THEN (SELECT $node_id FROM dbo.CampaignNode      WHERE CampaignID = @NodeID)
        WHEN 'technique'     THEN (SELECT $node_id FROM dbo.TechniqueNode     WHERE TechniqueID = @NodeID)
        WHEN 'vulnerability' THEN (SELECT $node_id FROM dbo.VulnerabilityNode WHERE VulnerabilityID = @NodeID) END;
    DELETE FROM dbo.InvestigationIncludes WHERE $from_id = @from AND $to_id = @to;
    IF @@ROWCOUNT = 0 THROW 50063, N'Kayıt vakada yok.', 1;
    UPDATE dbo.Investigation SET UpdatedAt = SYSUTCDATETIME() WHERE InvestigationID = @InvestigationID;
END;
GO

GRANT INSERT, UPDATE, DELETE ON dbo.Investigation TO tip_analyst;
GRANT INSERT, DELETE ON dbo.InvestigationNote TO tip_analyst;
GRANT EXECUTE ON dbo.sp_InvestigationAddItem TO tip_analyst;
GRANT EXECUTE ON dbo.sp_InvestigationRemoveItem TO tip_analyst;
GO
