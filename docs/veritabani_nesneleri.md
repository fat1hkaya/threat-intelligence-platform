# Veritabanı nesneleri (otomatik üretildi)

> `python scripts/gen_docs.py` ile SQL Server sistem kataloğundan (sys.tables, sys.columns, sys.objects...) üretilmiştir.

## İlişkisel tablolar (51)

| Tablo | Satır | Sütunlar (PK **kalın**, FK → hedef) |
|---|---:|---|
| `ActorAlias` | 430 | **ActorID** → ThreatActor, **Alias**, AliasKey |
| `ActorMalware` | 1,225 | **ActorID** → ThreatActor, **MalwareID** → Malware, Confidence, EvidenceID → Evidence |
| `ActorTargetCountry` | 0 | **ActorID** → ThreatActor, **CountryCode** → Country |
| `ActorTargetSector` | 303 | **ActorID** → ThreatActor, **SectorID** → Sector |
| `ActorTechnique` | 4,815 | **ActorID** → ThreatActor, **TechniqueID** → Technique, Confidence, EvidenceID → Evidence |
| `AppUser` | 32 | **UserID**, Username, FullName, Email, PasswordHash, RoleID → Role, IsActive, CreatedAt, LastLoginAt |
| `AuditLog` | 1,096 | **AuditID**, TableName, RecordID, Action, ChangedBy → AppUser, ChangedAt, OldValues, NewValues |
| `AutonomousSystem` | 0 | **ASN**, Name, CountryCode |
| `Campaign` | 57 | **CampaignID**, ExternalID, Name, Description, ActorID → ThreatActor, AttributionEvidenceID → Evidence, StartDate, EndDate, CreatedAt, UpdatedAt |
| `CampaignIndicator` | 0 | **CampaignID** → Campaign, **IndicatorID** → Indicator, Confidence, EvidenceID → Evidence |
| `CampaignMalware` | 173 | **CampaignID** → Campaign, **MalwareID** → Malware, Confidence, EvidenceID → Evidence |
| `CampaignTechnique` | 1,213 | **CampaignID** → Campaign, **TechniqueID** → Technique, Confidence, EvidenceID → Evidence |
| `Country` | 40 | **CountryCode**, Name |
| `DetectionCoverage` | 0 | **TechniqueID** → Technique, Level, DataSource, Note, UpdatedBy → AppUser, UpdatedAt |
| `Evidence` | 27,229 | **EvidenceID**, SourceID → Source, Summary, Url, ExternalRef, CollectedAt |
| `HuntMatch` | 7 | **HuntID** → HuntRun, **IndicatorID** → Indicator, MatchKind, Hits, FirstLine, LogValue, SampleLine |
| `HuntRun` | 34 | **HuntID**, StartedBy → AppUser, StartedAt, Location, FileName, LinesScanned, Candidates, Matches, Recorded |
| `ImportJob` | 198 | **JobID**, SourceID → Source, JobType, FileName, IsStrict, StartedBy → AppUser, StartedAt, FinishedAt, Status, RowsRead, RowsInserted, RowsUpdated, RowsSkipped, RowsFailed, ErrorMessage |
| `ImportJobError` | 192 | **ErrorID**, JobID → ImportJob, RowNo, RawValue, Reason |
| `Indicator` | 10,226 | **IndicatorID**, TypeID → IndicatorType, Value, NormalizedValue, Confidence, SeverityID → SeverityLevel, TLPID → TLPLevel, SourceID → Source, Status, Description, FirstSeen, LastSeen, ExpiresAt, CreatedBy → AppUser, CreatedAt, UpdatedAt, RowVer, ValidFrom, ValidTo |
| `IndicatorHistory` | 213 | IndicatorID, TypeID, Value, NormalizedValue, Confidence, SeverityID, TLPID, SourceID, Status, Description, FirstSeen, LastSeen, ExpiresAt, CreatedBy, CreatedAt, UpdatedAt, RowVer, ValidFrom, ValidTo |
| `IndicatorNetwork` | 790 | **IndicatorID** → Indicator, IpNum, ASN → AutonomousSystem, CountryCode, EnrichedAt |
| `IndicatorTag` | 16,756 | **IndicatorID** → Indicator, **TagID** → Tag |
| `IndicatorType` | 8 | **TypeID**, Code, Name |
| `Investigation` | 0 | **InvestigationID**, Title, Summary, Status, SeverityID → SeverityLevel, CreatedBy → AppUser, AssignedTo → AppUser, CreatedAt, UpdatedAt, ClosedAt |
| `InvestigationNote` | 0 | **NoteID**, InvestigationID → Investigation, AuthorID → AppUser, CreatedAt, Body |
| `IpRange` | 0 | **StartIP**, EndIP, ASN → AutonomousSystem, CountryCode |
| `LoginAttempt` | 240 | **AttemptID**, Username, UserID → AppUser, AttemptedAt, Success, ClientIP, Reason |
| `MaintenanceRun` | 47 | **RunID**, Task, StartedAt, FinishedAt, RowsAffected, Status, Message |
| `Malware` | 972 | **MalwareID**, ExternalID, Name, MalwareTypeID → MalwareType, Description, Platforms, CreatedAt, UpdatedAt, NameKey |
| `MalwareAlias` | 594 | **MalwareID** → Malware, **Alias**, AliasKey |
| `MalwareIndicator` | 8,060 | **MalwareID** → Malware, **IndicatorID** → Indicator, Role, Confidence, EvidenceID → Evidence, ValidFrom, ValidTo |
| `MalwareIndicatorHistory` | 58 | MalwareID, IndicatorID, Role, Confidence, EvidenceID, ValidFrom, ValidTo |
| `MalwareTechnique` | 11,608 | **MalwareID** → Malware, **TechniqueID** → Technique, Confidence, EvidenceID → Evidence |
| `MalwareType` | 12 | **MalwareTypeID**, Code, Name |
| `MalwareVulnerability` | 0 | **MalwareID** → Malware, **VulnerabilityID** → Vulnerability, Confidence, EvidenceID → Evidence |
| `Motivation` | 5 | **MotivationID**, Name |
| `RetentionPolicy` | 11 | **PolicyID**, SourceID → Source, TypeID → IndicatorType, LifetimeDays, Note |
| `Role` | 3 | **RoleID**, Code, Name |
| `Sector` | 14 | **SectorID**, Name |
| `SeverityLevel` | 5 | **SeverityID**, Code, Name, Weight |
| `Sighting` | 0 | **SightingID**, IndicatorID → Indicator, SightedAt, Quantity, Location, Note, ReportedBy → AppUser, HuntID → HuntRun |
| `Source` | 9 | **SourceID**, Name, Url, Reliability, Description, IsActive |
| `Tactic` | 15 | **TacticID**, ExternalID, ShortName, Name, Description, DisplayOrder |
| `Tag` | 444 | **TagID**, Name |
| `Technique` | 706 | **TechniqueID**, ExternalID, Name, Description, ParentTechniqueID → Technique |
| `TechniqueTactic` | 881 | **TechniqueID** → Technique, **TacticID** → Tactic |
| `ThreatActor` | 178 | **ActorID**, ExternalID, Name, Description, MotivationID → Motivation, CountryCode → Country, FirstSeen, LastSeen, IsActive, CreatedAt, UpdatedAt, NameKey |
| `TLPLevel` | 4 | **TLPID**, Code, Description |
| `UserSession` | 73 | **Token**, UserID → AppUser, CreatedAt, ExpiresAt |
| `Vulnerability` | 1,781 | **VulnerabilityID**, CveID, Title, Description, Vendor, Product, CvssScore, PublishedDate, IsKnownExploited |

## Graf düğüm tabloları (AS NODE) (7)

| Tablo | Satır | Kullanıcı sütunları |
|---|---:|---|
| `ActorNode` | 178 | ActorID |
| `CampaignNode` | 57 | CampaignID |
| `IndicatorNode` | 10,226 | IndicatorID |
| `InvestigationNode` | 0 | InvestigationID |
| `MalwareNode` | 972 | MalwareID |
| `TechniqueNode` | 706 | TechniqueID |
| `VulnerabilityNode` | 1,781 | VulnerabilityID |

## Graf kenar tabloları (AS EDGE) (11)

| Tablo | Satır | Kullanıcı sütunları |
|---|---:|---|
| `ActorSharesToolsWith` | 964 | SharedCount |
| `ActorUsesMalware` | 1,225 | Confidence, EvidenceID, CreatedAt |
| `ActorUsesTechnique` | 4,815 | Confidence, EvidenceID, CreatedAt |
| `CampaignAttributedToActor` | 25 | Confidence, EvidenceID, CreatedAt |
| `CampaignContainsIndicator` | 0 | Confidence, EvidenceID, CreatedAt |
| `CampaignUsesMalware` | 173 | Confidence, EvidenceID, CreatedAt |
| `CampaignUsesTechnique` | 1,213 | Confidence, EvidenceID, CreatedAt |
| `IndicatesMalware` | 8,060 | Role, Confidence, EvidenceID, CreatedAt |
| `InvestigationIncludes` | 0 | AddedBy, AddedAt, Note |
| `MalwareExploitsVulnerability` | 0 | Confidence, EvidenceID, CreatedAt |
| `MalwareUsesTechnique` | 11,608 | Confidence, EvidenceID, CreatedAt |

## Kenar kısıtları (CONNECTION)

| Kenar | Bağlantı | Silme |
|---|---|---|
| `ActorSharesToolsWith` | ActorNode → ActorNode | CASCADE |
| `ActorUsesMalware` | ActorNode → MalwareNode | CASCADE |
| `ActorUsesTechnique` | ActorNode → TechniqueNode | CASCADE |
| `CampaignAttributedToActor` | CampaignNode → ActorNode | CASCADE |
| `CampaignContainsIndicator` | CampaignNode → IndicatorNode | CASCADE |
| `CampaignUsesMalware` | CampaignNode → MalwareNode | CASCADE |
| `CampaignUsesTechnique` | CampaignNode → TechniqueNode | CASCADE |
| `IndicatesMalware` | IndicatorNode → MalwareNode | CASCADE |
| `InvestigationIncludes` | InvestigationNode → IndicatorNode | CASCADE |
| `InvestigationIncludes` | InvestigationNode → MalwareNode | CASCADE |
| `InvestigationIncludes` | InvestigationNode → ActorNode | CASCADE |
| `InvestigationIncludes` | InvestigationNode → CampaignNode | CASCADE |
| `InvestigationIncludes` | InvestigationNode → TechniqueNode | CASCADE |
| `InvestigationIncludes` | InvestigationNode → VulnerabilityNode | CASCADE |
| `MalwareExploitsVulnerability` | MalwareNode → VulnerabilityNode | CASCADE |
| `MalwareUsesTechnique` | MalwareNode → TechniqueNode | CASCADE |

## Görünümler (11)

`vw_ActorSummary`, `vw_CampaignSummary`, `vw_GraphEdge`, `vw_GraphNode`, `vw_Indicator`, `vw_IndicatorAttribution`, `vw_IndicatorCounts`, `vw_IndicatorNetwork`, `vw_InvestigationItem`, `vw_MalwareSummary`, `vw_SourceHealth`

## Saklı yordamlar (36)

`sp_ActorCoverage`, `sp_ActorShortestPath`, `sp_AddSighting`, `sp_AttackMatrix`, `sp_BulkImportIndicators`, `sp_CheckGraphConsistency`, `sp_CoverageOverview`, `sp_EndUserSessions`, `sp_EnrichNetwork`, `sp_ExpireIndicators`, `sp_FinishImportJob`, `sp_GetNeighborhood`, `sp_GlobalSearch`, `sp_GraphMaintenance`, `sp_HuntResult`, `sp_ImportAttackBundle`, `sp_ImportMalpedia`, `sp_IndicatorAsOf`, `sp_IndicatorCountsFast`, `sp_IndicatorKillChain`, `sp_IndicatorNetwork`, `sp_IndicatorStatsAsOf`, `sp_IndicatorVersions`, `sp_InfrastructureOverlap`, `sp_InvestigationAddItem`, `sp_InvestigationRemoveItem`, `sp_LoadIpRanges`, `sp_LoginAttempts`, `sp_MergeMalware`, `sp_RefreshActorSimilarity`, `sp_RetroHunt`, `sp_SaveIndicator`, `sp_StartImportJob`, `sp_SyncGraph`, `sp_TextSearch`, `sp_TopQueries`

## Skaler fonksiyonlar (5)

`fn_BigintToIpv4`, `fn_Ipv4ToBigint`, `fn_IsValidIndicator`, `fn_NameKey`, `fn_RiskScore`

## Satır içi tablo değerli fonksiyonlar (6)

`fn_ActorTechniques`, `fn_EffectiveCoverage`, `fn_FindMalware`, `fn_LifetimeDays`, `fn_LoginLock`, `fn_RiskBreakdown`

## Tetikleyiciler (27)

`trg_ActorMalware_GraphEdge`, `trg_ActorTechnique_GraphEdge`, `trg_AppUser_Audit`, `trg_AuditLog_Protect`, `trg_Campaign_Audit`, `trg_Campaign_GraphAttribution`, `trg_Campaign_GraphNode`, `trg_CampaignIndicator_GraphEdge`, `trg_CampaignMalware_GraphEdge`, `trg_CampaignTechnique_GraphEdge`, `trg_DetectionCoverage_Audit`, `trg_Indicator_Audit`, `trg_Indicator_GraphNode`, `trg_Indicator_Network`, `trg_Investigation_Audit`, `trg_Investigation_GraphNode`, `trg_Malware_Audit`, `trg_Malware_GraphNode`, `trg_MalwareIndicator_GraphEdge`, `trg_MalwareTechnique_GraphEdge`, `trg_MalwareVulnerability_GraphEdge`, `trg_Sighting_AfterInsert`, `trg_Technique_GraphNode`, `trg_Technique_Hierarchy`, `trg_ThreatActor_Audit`, `trg_ThreatActor_GraphNode`, `trg_Vulnerability_GraphNode`

## Kısıt ve indeks sayıları

CHECK: 46 · FOREIGN KEY: 71 · UNIQUE: 27 · DEFAULT: 59 · İndeks (PK dahil): 160

## Veritabanı rolleri

| Rol | GRANT | DENY |
|---|---:|---:|
| `tip_admin` | 13 | 0 |
| `tip_analyst` | 68 | 0 |
| `tip_reader` | 20 | 9 |
