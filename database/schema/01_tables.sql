/* =====================================================================
   ThreatLens - 01: Veritabanı ve tablolar (DDL)
   ---------------------------------------------------------------------
   Tasarım ilkeleri
   - Tüm tablolar 3NF/BCNF: çok değerli nitelikler (takma ad, etiket,
     hedef sektör...) ayrı tablolarda, M:N ilişkiler ara tablolarda.
   - Türetilmiş değerler (risk skoru, görülme sayısı) saklanmaz;
     görünüm ve fonksiyonlarla hesaplanır.
   - İş kuralları CHECK / UNIQUE / FK kısıtlarıyla veritabanında durur.
   - İlişkisel tablolar verinin asıl kaynağıdır. Aynı ilişkiler 05_graph.sql'de
     SQL Graph düğüm/kenar tablolarına yansıtılır.
   ===================================================================== */
IF DB_ID(N'ThreatLens') IS NULL
    CREATE DATABASE ThreatLens COLLATE Latin1_General_100_CI_AS;
GO
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ---------- 1. Sözlük (lookup) tabloları ---------- */

CREATE TABLE dbo.Role (
    RoleID      TINYINT       NOT NULL CONSTRAINT PK_Role PRIMARY KEY,
    Code        VARCHAR(20)   NOT NULL CONSTRAINT UQ_Role_Code UNIQUE,
    Name        NVARCHAR(50)  NOT NULL
);

CREATE TABLE dbo.AppUser (
    UserID       INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AppUser PRIMARY KEY,
    Username     NVARCHAR(50)  NOT NULL CONSTRAINT UQ_AppUser_Username UNIQUE,
    FullName     NVARCHAR(100) NOT NULL,
    Email        NVARCHAR(150) NULL,
    PasswordHash VARCHAR(200)  NOT NULL,
    RoleID       TINYINT       NOT NULL CONSTRAINT FK_AppUser_Role REFERENCES dbo.Role(RoleID),
    IsActive     BIT           NOT NULL CONSTRAINT DF_AppUser_IsActive DEFAULT (1),
    CreatedAt    DATETIME2(0)  NOT NULL CONSTRAINT DF_AppUser_CreatedAt DEFAULT (SYSUTCDATETIME()),
    LastLoginAt  DATETIME2(0)  NULL,
    CONSTRAINT CK_AppUser_Email CHECK (Email IS NULL OR Email LIKE N'%_@_%._%')
);

CREATE TABLE dbo.UserSession (
    Token      CHAR(64)     NOT NULL CONSTRAINT PK_UserSession PRIMARY KEY,
    UserID     INT          NOT NULL CONSTRAINT FK_UserSession_AppUser REFERENCES dbo.AppUser(UserID) ON DELETE CASCADE,
    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_UserSession_CreatedAt DEFAULT (SYSUTCDATETIME()),
    ExpiresAt  DATETIME2(0) NOT NULL
);

CREATE TABLE dbo.IndicatorType (
    TypeID  TINYINT      NOT NULL CONSTRAINT PK_IndicatorType PRIMARY KEY,
    Code    VARCHAR(10)  NOT NULL CONSTRAINT UQ_IndicatorType_Code UNIQUE,
    Name    NVARCHAR(50) NOT NULL
);

CREATE TABLE dbo.SeverityLevel (
    SeverityID TINYINT      NOT NULL CONSTRAINT PK_SeverityLevel PRIMARY KEY,
    Code       VARCHAR(10)  NOT NULL CONSTRAINT UQ_SeverityLevel_Code UNIQUE,
    Name       NVARCHAR(30) NOT NULL,
    Weight     TINYINT      NOT NULL,
    CONSTRAINT CK_SeverityLevel_Weight CHECK (Weight BETWEEN 0 AND 100)
);

/* Traffic Light Protocol: bilginin kimlerle paylaşılabileceği */
CREATE TABLE dbo.TLPLevel (
    TLPID       TINYINT       NOT NULL CONSTRAINT PK_TLPLevel PRIMARY KEY,
    Code        VARCHAR(12)   NOT NULL CONSTRAINT UQ_TLPLevel_Code UNIQUE,
    Description NVARCHAR(200) NOT NULL
);

CREATE TABLE dbo.Country (
    CountryCode CHAR(2)      NOT NULL CONSTRAINT PK_Country PRIMARY KEY,
    Name        NVARCHAR(80) NOT NULL CONSTRAINT UQ_Country_Name UNIQUE,
    CONSTRAINT CK_Country_Code CHECK (CountryCode LIKE '[A-Z][A-Z]')
);

CREATE TABLE dbo.Sector (
    SectorID SMALLINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Sector PRIMARY KEY,
    Name     NVARCHAR(80) NOT NULL CONSTRAINT UQ_Sector_Name UNIQUE
);

CREATE TABLE dbo.Motivation (
    MotivationID TINYINT      NOT NULL CONSTRAINT PK_Motivation PRIMARY KEY,
    Name         NVARCHAR(50) NOT NULL CONSTRAINT UQ_Motivation_Name UNIQUE
);

CREATE TABLE dbo.MalwareType (
    MalwareTypeID TINYINT      NOT NULL CONSTRAINT PK_MalwareType PRIMARY KEY,
    Code          VARCHAR(20)  NOT NULL CONSTRAINT UQ_MalwareType_Code UNIQUE,
    Name          NVARCHAR(50) NOT NULL
);

/* İstihbarat kaynağı. Reliability: Admiralty ölçeği (A en güvenilir, F değerlendirilemez) */
CREATE TABLE dbo.Source (
    SourceID    SMALLINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Source PRIMARY KEY,
    Name        NVARCHAR(100) NOT NULL CONSTRAINT UQ_Source_Name UNIQUE,
    Url         NVARCHAR(300) NULL,
    Reliability CHAR(1)       NOT NULL CONSTRAINT DF_Source_Reliability DEFAULT ('C'),
    Description NVARCHAR(400) NULL,
    IsActive    BIT           NOT NULL CONSTRAINT DF_Source_IsActive DEFAULT (1),
    CONSTRAINT CK_Source_Reliability CHECK (Reliability IN ('A','B','C','D','E','F'))
);

CREATE TABLE dbo.Tag (
    TagID SMALLINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Tag PRIMARY KEY,
    Name  NVARCHAR(50) NOT NULL CONSTRAINT UQ_Tag_Name UNIQUE
);

/* Kanıt: bir ilişkinin (ör. "APT28, X-Agent kullanır") hangi kaynağa ve hangi
   açıklamaya dayandığı. Kaynak, kanıt üzerinden bilinir; ilişki tablolarında
   ayrıca SourceID tutulmaz (aksi halde EvidenceID -> SourceID geçişli bağımlılık olurdu). */
CREATE TABLE dbo.Evidence (
    EvidenceID  INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Evidence PRIMARY KEY,
    SourceID    SMALLINT       NOT NULL CONSTRAINT FK_Evidence_Source REFERENCES dbo.Source(SourceID),
    Summary     NVARCHAR(1000) NOT NULL,
    Url         NVARCHAR(400)  NULL,
    ExternalRef VARCHAR(100)   NULL,      -- kaynaktaki kimlik, ör. STIX relationship--uuid
    CollectedAt DATETIME2(0)   NOT NULL CONSTRAINT DF_Evidence_CollectedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT CK_Evidence_Summary CHECK (LEN(Summary) > 0)
);

/* ---------- 2. MITRE ATT&CK bilgi tabanı ---------- */

CREATE TABLE dbo.Tactic (
    TacticID     SMALLINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Tactic PRIMARY KEY,
    ExternalID   VARCHAR(10)   NOT NULL CONSTRAINT UQ_Tactic_ExternalID UNIQUE,   -- TA0001
    ShortName    VARCHAR(50)   NOT NULL CONSTRAINT UQ_Tactic_ShortName UNIQUE,    -- initial-access
    Name         NVARCHAR(100) NOT NULL,
    Description  NVARCHAR(1000) NULL,
    DisplayOrder TINYINT       NOT NULL
);

/* Alt teknik (T1059.001) üst tekniğe (T1059) özyinelemeli FK ile bağlanır */
CREATE TABLE dbo.Technique (
    TechniqueID       INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Technique PRIMARY KEY,
    ExternalID        VARCHAR(12)    NOT NULL CONSTRAINT UQ_Technique_ExternalID UNIQUE,
    Name              NVARCHAR(150)  NOT NULL,
    Description       NVARCHAR(1500) NULL,
    ParentTechniqueID INT NULL CONSTRAINT FK_Technique_Parent REFERENCES dbo.Technique(TechniqueID),
    CONSTRAINT CK_Technique_NotOwnParent CHECK (ParentTechniqueID IS NULL OR ParentTechniqueID <> TechniqueID)
);

CREATE TABLE dbo.TechniqueTactic (
    TechniqueID INT      NOT NULL CONSTRAINT FK_TechniqueTactic_Technique REFERENCES dbo.Technique(TechniqueID) ON DELETE CASCADE,
    TacticID    SMALLINT NOT NULL CONSTRAINT FK_TechniqueTactic_Tactic REFERENCES dbo.Tactic(TacticID) ON DELETE CASCADE,
    CONSTRAINT PK_TechniqueTactic PRIMARY KEY (TechniqueID, TacticID)
);

/* ---------- 3. Çekirdek varlıklar ---------- */

CREATE TABLE dbo.ThreatActor (
    ActorID      INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ThreatActor PRIMARY KEY,
    ExternalID   VARCHAR(12)    NULL,                                   -- MITRE G0007
    Name         NVARCHAR(100)  NOT NULL CONSTRAINT UQ_ThreatActor_Name UNIQUE,
    Description  NVARCHAR(2000) NULL,
    MotivationID TINYINT NULL CONSTRAINT FK_ThreatActor_Motivation REFERENCES dbo.Motivation(MotivationID),
    CountryCode  CHAR(2) NULL CONSTRAINT FK_ThreatActor_Country REFERENCES dbo.Country(CountryCode),
    FirstSeen    DATE NULL,
    LastSeen     DATE NULL,
    IsActive     BIT          NOT NULL CONSTRAINT DF_ThreatActor_IsActive DEFAULT (1),
    CreatedAt    DATETIME2(0) NOT NULL CONSTRAINT DF_ThreatActor_CreatedAt DEFAULT (SYSUTCDATETIME()),
    UpdatedAt    DATETIME2(0) NOT NULL CONSTRAINT DF_ThreatActor_UpdatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT CK_ThreatActor_Dates CHECK (LastSeen IS NULL OR FirstSeen IS NULL OR LastSeen >= FirstSeen)
);

/* Çok değerli nitelik: bir aktörün birden çok takma adı olur (APT28 = Fancy Bear = Sofacy) */
CREATE TABLE dbo.ActorAlias (
    ActorID INT           NOT NULL CONSTRAINT FK_ActorAlias_ThreatActor REFERENCES dbo.ThreatActor(ActorID) ON DELETE CASCADE,
    Alias   NVARCHAR(100) NOT NULL,
    CONSTRAINT PK_ActorAlias PRIMARY KEY (ActorID, Alias)
);

CREATE TABLE dbo.Malware (
    MalwareID     INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Malware PRIMARY KEY,
    ExternalID    VARCHAR(12)    NULL,                                  -- MITRE S0002
    Name          NVARCHAR(100)  NOT NULL CONSTRAINT UQ_Malware_Name UNIQUE,
    MalwareTypeID TINYINT        NOT NULL CONSTRAINT FK_Malware_MalwareType REFERENCES dbo.MalwareType(MalwareTypeID),
    Description   NVARCHAR(2000) NULL,
    Platforms     NVARCHAR(200)  NULL,
    CreatedAt     DATETIME2(0)   NOT NULL CONSTRAINT DF_Malware_CreatedAt DEFAULT (SYSUTCDATETIME()),
    UpdatedAt     DATETIME2(0)   NOT NULL CONSTRAINT DF_Malware_UpdatedAt DEFAULT (SYSUTCDATETIME())
);

CREATE TABLE dbo.MalwareAlias (
    MalwareID INT           NOT NULL CONSTRAINT FK_MalwareAlias_Malware REFERENCES dbo.Malware(MalwareID) ON DELETE CASCADE,
    Alias     NVARCHAR(100) NOT NULL,
    CONSTRAINT PK_MalwareAlias PRIMARY KEY (MalwareID, Alias)
);

CREATE TABLE dbo.Campaign (
    CampaignID  INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Campaign PRIMARY KEY,
    ExternalID  VARCHAR(12)    NULL,                                    -- MITRE C0022
    Name        NVARCHAR(150)  NOT NULL CONSTRAINT UQ_Campaign_Name UNIQUE,
    Description NVARCHAR(2000) NULL,
    ActorID     INT NULL CONSTRAINT FK_Campaign_ThreatActor REFERENCES dbo.ThreatActor(ActorID) ON DELETE SET NULL,
    AttributionEvidenceID INT NULL CONSTRAINT FK_Campaign_Evidence REFERENCES dbo.Evidence(EvidenceID),
    StartDate   DATE NULL,
    EndDate     DATE NULL,
    CreatedAt   DATETIME2(0) NOT NULL CONSTRAINT DF_Campaign_CreatedAt DEFAULT (SYSUTCDATETIME()),
    UpdatedAt   DATETIME2(0) NOT NULL CONSTRAINT DF_Campaign_UpdatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT CK_Campaign_Dates CHECK (EndDate IS NULL OR StartDate IS NULL OR EndDate >= StartDate)
);

CREATE TABLE dbo.Vulnerability (
    VulnerabilityID INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Vulnerability PRIMARY KEY,
    CveID           VARCHAR(20)    NOT NULL CONSTRAINT UQ_Vulnerability_CveID UNIQUE,
    Title           NVARCHAR(300)  NOT NULL,
    Description     NVARCHAR(2000) NULL,
    Vendor          NVARCHAR(100)  NULL,
    Product         NVARCHAR(150)  NULL,
    CvssScore       DECIMAL(3,1)   NULL,
    PublishedDate   DATE           NULL,
    IsKnownExploited BIT           NOT NULL CONSTRAINT DF_Vulnerability_IsKev DEFAULT (0),
    CONSTRAINT CK_Vulnerability_CveID CHECK (CveID LIKE 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]%'),
    CONSTRAINT CK_Vulnerability_Cvss  CHECK (CvssScore IS NULL OR CvssScore BETWEEN 0 AND 10)
);

/* Gösterge (IOC): platformun en yoğun tablosu.
   Value: kaynaktan geldiği hâliyle (ör. hxxp://evil[.]com). NormalizedValue: uygulama
   katmanında (app/services/normalize.py) üretilen kanonik biçim; tekrar denetimi ve arama
   bunun üzerinden yapılır. Bilinçli türetilmiş nitelik: NormalizedValue, Value'nun
   fonksiyonudur (Value -> NormalizedValue); tekrarı önleyen benzersizlik kısıtı için saklanır.
   RowVer: iyimser eşzamanlılık denetimi (iki analist aynı kaydı aynı anda düzenlerse). */
CREATE TABLE dbo.Indicator (
    IndicatorID     BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Indicator PRIMARY KEY,
    TypeID          TINYINT        NOT NULL CONSTRAINT FK_Indicator_IndicatorType REFERENCES dbo.IndicatorType(TypeID),
    Value           NVARCHAR(400)  NOT NULL,
    NormalizedValue NVARCHAR(400)  NOT NULL,
    Confidence      TINYINT        NOT NULL CONSTRAINT DF_Indicator_Confidence DEFAULT (50),
    SeverityID      TINYINT        NOT NULL CONSTRAINT FK_Indicator_SeverityLevel REFERENCES dbo.SeverityLevel(SeverityID),
    TLPID           TINYINT        NOT NULL CONSTRAINT FK_Indicator_TLPLevel REFERENCES dbo.TLPLevel(TLPID),
    SourceID        SMALLINT       NOT NULL CONSTRAINT FK_Indicator_Source REFERENCES dbo.Source(SourceID),
    Status          VARCHAR(15)    NOT NULL CONSTRAINT DF_Indicator_Status DEFAULT ('active'),
    Description     NVARCHAR(1000) NULL,
    FirstSeen       DATETIME2(0)   NOT NULL CONSTRAINT DF_Indicator_FirstSeen DEFAULT (SYSUTCDATETIME()),
    LastSeen        DATETIME2(0)   NOT NULL CONSTRAINT DF_Indicator_LastSeen DEFAULT (SYSUTCDATETIME()),
    ExpiresAt       DATETIME2(0)   NULL,
    CreatedBy       INT NULL CONSTRAINT FK_Indicator_AppUser REFERENCES dbo.AppUser(UserID),
    CreatedAt       DATETIME2(0)   NOT NULL CONSTRAINT DF_Indicator_CreatedAt DEFAULT (SYSUTCDATETIME()),
    UpdatedAt       DATETIME2(0)   NOT NULL CONSTRAINT DF_Indicator_UpdatedAt DEFAULT (SYSUTCDATETIME()),
    RowVer          ROWVERSION     NOT NULL,
    CONSTRAINT UQ_Indicator_Type_Normalized UNIQUE (TypeID, NormalizedValue),   -- aynı gösterge iki kez girilemez
    CONSTRAINT CK_Indicator_Confidence CHECK (Confidence BETWEEN 0 AND 100),
    CONSTRAINT CK_Indicator_Status     CHECK (Status IN ('active', 'expired', 'revoked', 'false_positive')),
    CONSTRAINT CK_Indicator_Seen       CHECK (LastSeen >= FirstSeen),
    CONSTRAINT CK_Indicator_Value      CHECK (LEN(Value) > 0 AND LEN(NormalizedValue) > 0)
);

/* Göstergenin kurum içinde (SIEM, EDR, e-posta ağ geçidi...) görülmesi */
CREATE TABLE dbo.Sighting (
    SightingID  BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Sighting PRIMARY KEY,
    IndicatorID BIGINT        NOT NULL CONSTRAINT FK_Sighting_Indicator REFERENCES dbo.Indicator(IndicatorID) ON DELETE CASCADE,
    SightedAt   DATETIME2(0)  NOT NULL CONSTRAINT DF_Sighting_SightedAt DEFAULT (SYSUTCDATETIME()),
    Quantity    INT           NOT NULL CONSTRAINT DF_Sighting_Quantity DEFAULT (1),
    Location    NVARCHAR(100) NULL,           -- nerede görüldü: 'SIEM', 'EDR / WS-0142'...
    Note        NVARCHAR(400) NULL,
    ReportedBy  INT NULL CONSTRAINT FK_Sighting_AppUser REFERENCES dbo.AppUser(UserID),
    CONSTRAINT CK_Sighting_Quantity CHECK (Quantity > 0)
);

/* ---------- 4. M:N ilişki (ara) tabloları ----------
   Her ilişki satırı isteğe bağlı olarak güven puanı ve kanıt taşır:
   "bu bağlantıyı neden kurduk, hangi kaynak söylüyor?" */

CREATE TABLE dbo.IndicatorTag (
    IndicatorID BIGINT   NOT NULL CONSTRAINT FK_IndicatorTag_Indicator REFERENCES dbo.Indicator(IndicatorID) ON DELETE CASCADE,
    TagID       SMALLINT NOT NULL CONSTRAINT FK_IndicatorTag_Tag REFERENCES dbo.Tag(TagID) ON DELETE CASCADE,
    CONSTRAINT PK_IndicatorTag PRIMARY KEY (IndicatorID, TagID)
);

CREATE TABLE dbo.ActorMalware (
    ActorID   INT NOT NULL CONSTRAINT FK_ActorMalware_ThreatActor REFERENCES dbo.ThreatActor(ActorID) ON DELETE CASCADE,
    MalwareID INT NOT NULL CONSTRAINT FK_ActorMalware_Malware REFERENCES dbo.Malware(MalwareID) ON DELETE CASCADE,
    Confidence  TINYINT NULL CONSTRAINT CK_ActorMalware_Confidence CHECK (Confidence BETWEEN 0 AND 100),
    EvidenceID  INT NULL CONSTRAINT FK_ActorMalware_Evidence REFERENCES dbo.Evidence(EvidenceID) ON DELETE SET NULL,
    CONSTRAINT PK_ActorMalware PRIMARY KEY (ActorID, MalwareID)
);

CREATE TABLE dbo.ActorTechnique (
    ActorID     INT NOT NULL CONSTRAINT FK_ActorTechnique_ThreatActor REFERENCES dbo.ThreatActor(ActorID) ON DELETE CASCADE,
    TechniqueID INT NOT NULL CONSTRAINT FK_ActorTechnique_Technique REFERENCES dbo.Technique(TechniqueID) ON DELETE CASCADE,
    Confidence  TINYINT NULL CONSTRAINT CK_ActorTechnique_Confidence CHECK (Confidence BETWEEN 0 AND 100),
    EvidenceID  INT NULL CONSTRAINT FK_ActorTechnique_Evidence REFERENCES dbo.Evidence(EvidenceID) ON DELETE SET NULL,
    CONSTRAINT PK_ActorTechnique PRIMARY KEY (ActorID, TechniqueID)
);

CREATE TABLE dbo.ActorTargetSector (
    ActorID  INT      NOT NULL CONSTRAINT FK_ActorTargetSector_ThreatActor REFERENCES dbo.ThreatActor(ActorID) ON DELETE CASCADE,
    SectorID SMALLINT NOT NULL CONSTRAINT FK_ActorTargetSector_Sector REFERENCES dbo.Sector(SectorID) ON DELETE CASCADE,
    CONSTRAINT PK_ActorTargetSector PRIMARY KEY (ActorID, SectorID)
);

CREATE TABLE dbo.ActorTargetCountry (
    ActorID     INT     NOT NULL CONSTRAINT FK_ActorTargetCountry_ThreatActor REFERENCES dbo.ThreatActor(ActorID) ON DELETE CASCADE,
    CountryCode CHAR(2) NOT NULL CONSTRAINT FK_ActorTargetCountry_Country REFERENCES dbo.Country(CountryCode),
    CONSTRAINT PK_ActorTargetCountry PRIMARY KEY (ActorID, CountryCode)
);

CREATE TABLE dbo.MalwareTechnique (
    MalwareID   INT NOT NULL CONSTRAINT FK_MalwareTechnique_Malware REFERENCES dbo.Malware(MalwareID) ON DELETE CASCADE,
    TechniqueID INT NOT NULL CONSTRAINT FK_MalwareTechnique_Technique REFERENCES dbo.Technique(TechniqueID) ON DELETE CASCADE,
    Confidence  TINYINT NULL CONSTRAINT CK_MalwareTechnique_Confidence CHECK (Confidence BETWEEN 0 AND 100),
    EvidenceID  INT NULL CONSTRAINT FK_MalwareTechnique_Evidence REFERENCES dbo.Evidence(EvidenceID) ON DELETE SET NULL,
    CONSTRAINT PK_MalwareTechnique PRIMARY KEY (MalwareID, TechniqueID)
);

CREATE TABLE dbo.MalwareVulnerability (
    MalwareID       INT NOT NULL CONSTRAINT FK_MalwareVulnerability_Malware REFERENCES dbo.Malware(MalwareID) ON DELETE CASCADE,
    VulnerabilityID INT NOT NULL CONSTRAINT FK_MalwareVulnerability_Vulnerability REFERENCES dbo.Vulnerability(VulnerabilityID) ON DELETE CASCADE,
    Confidence  TINYINT NULL CONSTRAINT CK_MalwareVulnerability_Confidence CHECK (Confidence BETWEEN 0 AND 100),
    EvidenceID  INT NULL CONSTRAINT FK_MalwareVulnerability_Evidence REFERENCES dbo.Evidence(EvidenceID) ON DELETE SET NULL,
    CONSTRAINT PK_MalwareVulnerability PRIMARY KEY (MalwareID, VulnerabilityID)
);

/* İlişkinin kendi niteliği var: gösterge zararlıda hangi rolü oynuyor? */
CREATE TABLE dbo.MalwareIndicator (
    MalwareID   INT    NOT NULL CONSTRAINT FK_MalwareIndicator_Malware REFERENCES dbo.Malware(MalwareID) ON DELETE CASCADE,
    IndicatorID BIGINT NOT NULL CONSTRAINT FK_MalwareIndicator_Indicator REFERENCES dbo.Indicator(IndicatorID) ON DELETE CASCADE,
    Role        VARCHAR(12) NOT NULL CONSTRAINT DF_MalwareIndicator_Role DEFAULT ('other'),
    Confidence  TINYINT NULL CONSTRAINT CK_MalwareIndicator_Confidence CHECK (Confidence BETWEEN 0 AND 100),
    EvidenceID  INT NULL CONSTRAINT FK_MalwareIndicator_Evidence REFERENCES dbo.Evidence(EvidenceID) ON DELETE SET NULL,
    CONSTRAINT PK_MalwareIndicator PRIMARY KEY (MalwareID, IndicatorID),
    CONSTRAINT CK_MalwareIndicator_Role CHECK (Role IN ('c2','payload','dropper','exfil','phishing','other'))
);

CREATE TABLE dbo.CampaignMalware (
    CampaignID INT NOT NULL CONSTRAINT FK_CampaignMalware_Campaign REFERENCES dbo.Campaign(CampaignID) ON DELETE CASCADE,
    MalwareID  INT NOT NULL CONSTRAINT FK_CampaignMalware_Malware REFERENCES dbo.Malware(MalwareID) ON DELETE CASCADE,
    Confidence  TINYINT NULL CONSTRAINT CK_CampaignMalware_Confidence CHECK (Confidence BETWEEN 0 AND 100),
    EvidenceID  INT NULL CONSTRAINT FK_CampaignMalware_Evidence REFERENCES dbo.Evidence(EvidenceID) ON DELETE SET NULL,
    CONSTRAINT PK_CampaignMalware PRIMARY KEY (CampaignID, MalwareID)
);

CREATE TABLE dbo.CampaignTechnique (
    CampaignID  INT NOT NULL CONSTRAINT FK_CampaignTechnique_Campaign REFERENCES dbo.Campaign(CampaignID) ON DELETE CASCADE,
    TechniqueID INT NOT NULL CONSTRAINT FK_CampaignTechnique_Technique REFERENCES dbo.Technique(TechniqueID) ON DELETE CASCADE,
    Confidence  TINYINT NULL CONSTRAINT CK_CampaignTechnique_Confidence CHECK (Confidence BETWEEN 0 AND 100),
    EvidenceID  INT NULL CONSTRAINT FK_CampaignTechnique_Evidence REFERENCES dbo.Evidence(EvidenceID) ON DELETE SET NULL,
    CONSTRAINT PK_CampaignTechnique PRIMARY KEY (CampaignID, TechniqueID)
);

CREATE TABLE dbo.CampaignIndicator (
    CampaignID  INT    NOT NULL CONSTRAINT FK_CampaignIndicator_Campaign REFERENCES dbo.Campaign(CampaignID) ON DELETE CASCADE,
    IndicatorID BIGINT NOT NULL CONSTRAINT FK_CampaignIndicator_Indicator REFERENCES dbo.Indicator(IndicatorID) ON DELETE CASCADE,
    Confidence  TINYINT NULL CONSTRAINT CK_CampaignIndicator_Confidence CHECK (Confidence BETWEEN 0 AND 100),
    EvidenceID  INT NULL CONSTRAINT FK_CampaignIndicator_Evidence REFERENCES dbo.Evidence(EvidenceID) ON DELETE SET NULL,
    CONSTRAINT PK_CampaignIndicator PRIMARY KEY (CampaignID, IndicatorID)
);

/* ---------- 5. İşletim tabloları ---------- */

/* İçe aktarma işi: besleme, dosya yükleme veya ATT&CK güncellemesi */
CREATE TABLE dbo.ImportJob (
    JobID        INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ImportJob PRIMARY KEY,
    SourceID     SMALLINT      NOT NULL CONSTRAINT FK_ImportJob_Source REFERENCES dbo.Source(SourceID),
    JobType      VARCHAR(10)   NOT NULL CONSTRAINT DF_ImportJob_JobType DEFAULT ('feed'),
    FileName     NVARCHAR(200) NULL,
    IsStrict     BIT           NOT NULL CONSTRAINT DF_ImportJob_IsStrict DEFAULT (0),   -- 1: hepsi ya da hiçbiri
    StartedBy    INT NULL CONSTRAINT FK_ImportJob_AppUser REFERENCES dbo.AppUser(UserID),
    StartedAt    DATETIME2(0)  NOT NULL CONSTRAINT DF_ImportJob_StartedAt DEFAULT (SYSUTCDATETIME()),
    FinishedAt   DATETIME2(0)  NULL,
    Status       VARCHAR(10)   NOT NULL CONSTRAINT DF_ImportJob_Status DEFAULT ('running'),
    RowsRead     INT NOT NULL CONSTRAINT DF_ImportJob_RowsRead DEFAULT (0),
    RowsInserted INT NOT NULL CONSTRAINT DF_ImportJob_RowsInserted DEFAULT (0),
    RowsUpdated  INT NOT NULL CONSTRAINT DF_ImportJob_RowsUpdated DEFAULT (0),
    RowsSkipped  INT NOT NULL CONSTRAINT DF_ImportJob_RowsSkipped DEFAULT (0),
    RowsFailed   INT NOT NULL CONSTRAINT DF_ImportJob_RowsFailed DEFAULT (0),
    ErrorMessage NVARCHAR(1000) NULL,
    CONSTRAINT CK_ImportJob_JobType CHECK (JobType IN ('feed', 'file', 'attack', 'demo')),
    CONSTRAINT CK_ImportJob_Status  CHECK (Status IN ('running', 'success', 'partial', 'failed')),
    CONSTRAINT CK_ImportJob_Dates   CHECK (FinishedAt IS NULL OR FinishedAt >= StartedAt),
    CONSTRAINT CK_ImportJob_Rows    CHECK (RowsRead >= 0 AND RowsInserted >= 0 AND RowsUpdated >= 0 AND RowsSkipped >= 0 AND RowsFailed >= 0)
);

/* Reddedilen satırlar: hangi satır, hangi değer, neden */
CREATE TABLE dbo.ImportJobError (
    ErrorID  BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ImportJobError PRIMARY KEY,
    JobID    INT           NOT NULL CONSTRAINT FK_ImportJobError_ImportJob REFERENCES dbo.ImportJob(JobID) ON DELETE CASCADE,
    RowNo    INT           NOT NULL,
    RawValue NVARCHAR(400) NULL,
    Reason   NVARCHAR(300) NOT NULL
);

/* Denetim izi: tetikleyiciler tarafından doldurulur, uygulama doğrudan yazmaz */
CREATE TABLE dbo.AuditLog (
    AuditID   BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLog PRIMARY KEY,
    TableName SYSNAME       NOT NULL,
    RecordID  BIGINT        NOT NULL,
    Action    CHAR(1)       NOT NULL,
    ChangedBy INT NULL CONSTRAINT FK_AuditLog_AppUser REFERENCES dbo.AppUser(UserID),
    ChangedAt DATETIME2(3)  NOT NULL CONSTRAINT DF_AuditLog_ChangedAt DEFAULT (SYSUTCDATETIME()),
    OldValues NVARCHAR(MAX) NULL,
    NewValues NVARCHAR(MAX) NULL,
    CONSTRAINT CK_AuditLog_Action CHECK (Action IN ('I','U','D'))
);
GO

