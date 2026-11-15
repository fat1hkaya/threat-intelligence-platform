/* =====================================================================
   ThreatLens - 02: İndeksler (fiziksel tasarım)
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- PK ve UNIQUE kısıtları kendi indekslerini zaten oluşturur. Aşağıdakiler sık çalışan sorgular içindir.

-- Liste ekranı: en son görülenler önce; kapsayan (covering) sütunlarla key lookup'tan kaçınılır
CREATE NONCLUSTERED INDEX IX_Indicator_LastSeen
    ON dbo.Indicator (LastSeen DESC) INCLUDE (TypeID, NormalizedValue, Confidence, SeverityID, TLPID, SourceID, Status);
-- Değer araması (tip bilinmeden yapıştırılan IOC). UQ (TypeID, NormalizedValue) tipi bilinen aramayı zaten karşılar.
CREATE NONCLUSTERED INDEX IX_Indicator_NormalizedValue ON dbo.Indicator (NormalizedValue) INCLUDE (TypeID, Status);
-- Filtreli indeks: süresi dolacak aktif göstergeler (sp_ExpireIndicators)
CREATE NONCLUSTERED INDEX IX_Indicator_ExpiresAt_Active
    ON dbo.Indicator (ExpiresAt) WHERE Status = 'active' AND ExpiresAt IS NOT NULL;
CREATE NONCLUSTERED INDEX IX_Indicator_Source   ON dbo.Indicator (SourceID);
CREATE NONCLUSTERED INDEX IX_Indicator_FirstSeen ON dbo.Indicator (FirstSeen) INCLUDE (TypeID);

CREATE NONCLUSTERED INDEX IX_Sighting_Indicator ON dbo.Sighting (IndicatorID, SightedAt DESC) INCLUDE (Quantity);
CREATE NONCLUSTERED INDEX IX_Campaign_Actor     ON dbo.Campaign (ActorID);
CREATE NONCLUSTERED INDEX IX_Technique_Parent   ON dbo.Technique (ParentTechniqueID);
CREATE NONCLUSTERED INDEX IX_ImportJob_Source     ON dbo.ImportJob (SourceID, StartedAt DESC);
CREATE NONCLUSTERED INDEX IX_ImportJobError_Job   ON dbo.ImportJobError (JobID, RowNo);
CREATE NONCLUSTERED INDEX IX_Evidence_Source      ON dbo.Evidence (SourceID);
CREATE UNIQUE NONCLUSTERED INDEX UX_Evidence_ExternalRef ON dbo.Evidence (ExternalRef) WHERE ExternalRef IS NOT NULL;
CREATE NONCLUSTERED INDEX IX_AuditLog_Record    ON dbo.AuditLog (TableName, RecordID, ChangedAt DESC);
CREATE NONCLUSTERED INDEX IX_AuditLog_ChangedAt ON dbo.AuditLog (ChangedAt DESC);
CREATE NONCLUSTERED INDEX IX_UserSession_User   ON dbo.UserSession (UserID);
CREATE UNIQUE NONCLUSTERED INDEX UX_ThreatActor_ExternalID ON dbo.ThreatActor (ExternalID) WHERE ExternalID IS NOT NULL;
CREATE UNIQUE NONCLUSTERED INDEX UX_Malware_ExternalID     ON dbo.Malware (ExternalID)     WHERE ExternalID IS NOT NULL;
CREATE UNIQUE NONCLUSTERED INDEX UX_Campaign_ExternalID    ON dbo.Campaign (ExternalID)    WHERE ExternalID IS NOT NULL;

-- Ara tablolarda PK (A,B) yönünü karşılar; ters yön (B -> A) için ikinci indeks gerekir
CREATE NONCLUSTERED INDEX IX_ActorMalware_Malware           ON dbo.ActorMalware (MalwareID);
CREATE NONCLUSTERED INDEX IX_ActorTechnique_Technique       ON dbo.ActorTechnique (TechniqueID);
CREATE NONCLUSTERED INDEX IX_MalwareTechnique_Technique     ON dbo.MalwareTechnique (TechniqueID);
CREATE NONCLUSTERED INDEX IX_MalwareIndicator_Indicator     ON dbo.MalwareIndicator (IndicatorID);
CREATE NONCLUSTERED INDEX IX_CampaignIndicator_Indicator    ON dbo.CampaignIndicator (IndicatorID);
CREATE NONCLUSTERED INDEX IX_CampaignMalware_Malware        ON dbo.CampaignMalware (MalwareID);
CREATE NONCLUSTERED INDEX IX_CampaignTechnique_Technique    ON dbo.CampaignTechnique (TechniqueID);
CREATE NONCLUSTERED INDEX IX_MalwareVulnerability_Vuln      ON dbo.MalwareVulnerability (VulnerabilityID);
CREATE NONCLUSTERED INDEX IX_IndicatorTag_Tag               ON dbo.IndicatorTag (TagID);
CREATE NONCLUSTERED INDEX IX_TechniqueTactic_Tactic         ON dbo.TechniqueTactic (TacticID);
GO
