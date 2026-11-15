# Veritabanı nesneleri (otomatik üretildi)

> `python scripts/gen_docs.py` ile SQL Server sistem kataloğundan (sys.tables, sys.columns, sys.objects...) üretilmiştir.

## İlişkisel tablolar (38)

| Tablo | Satır | Sütunlar (PK **kalın**, FK → hedef) |
|---|---:|---|
| `ActorAlias` | 430 | **ActorID** → ThreatActor, **Alias** |
| `ActorMalware` | 1,166 | **ActorID** → ThreatActor, **MalwareID** → Malware, Confidence, EvidenceID → Evidence |
| `ActorTargetCountry` | 0 | **ActorID** → ThreatActor, **CountryCode** → Country |
| `ActorTargetSector` | 303 | **ActorID** → ThreatActor, **SectorID** → Sector |
| `ActorTechnique` | 4,815 | **ActorID** → ThreatActor, **TechniqueID** → Technique, Confidence, EvidenceID → Evidence |
| `AppUser` | 3 | **UserID**, Username, FullName, Email, PasswordHash, RoleID → Role, IsActive, CreatedAt, LastLoginAt |
| `AuditLog` | 36 | **AuditID**, TableName, RecordID, Action, ChangedBy → AppUser, ChangedAt, OldValues, NewValues |
| `Campaign` | 57 | **CampaignID**, ExternalID, Name, Description, ActorID → ThreatActor, AttributionEvidenceID → Evidence, StartDate, EndDate, CreatedAt, UpdatedAt |
| `CampaignIndicator` | 232 | **CampaignID** → Campaign, **IndicatorID** → Indicator, Confidence, EvidenceID → Evidence |
| `CampaignMalware` | 173 | **CampaignID** → Campaign, **MalwareID** → Malware, Confidence, EvidenceID → Evidence |
| `CampaignTechnique` | 1,213 | **CampaignID** → Campaign, **TechniqueID** → Technique, Confidence, EvidenceID → Evidence |
| `Country` | 40 | **CountryCode**, Name |
| `Evidence` | 20,462 | **EvidenceID**, SourceID → Source, Summary, Url, ExternalRef, CollectedAt |
| `ImportJob` | 10 | **JobID**, SourceID → Source, JobType, FileName, IsStrict, StartedBy → AppUser, StartedAt, FinishedAt, Status, RowsRead, RowsInserted, RowsUpdated, RowsSkipped, RowsFailed, ErrorMessage |
| `ImportJobError` | 12 | **ErrorID**, JobID → ImportJob, RowNo, RawValue, Reason |
| `Indicator` | 1,446 | **IndicatorID**, TypeID → IndicatorType, Value, NormalizedValue, Confidence, SeverityID → SeverityLevel, TLPID → TLPLevel, SourceID → Source, Status, Description, FirstSeen, LastSeen, ExpiresAt, CreatedBy → AppUser, CreatedAt, UpdatedAt, RowVer |
| `IndicatorTag` | 3,908 | **IndicatorID** → Indicator, **TagID** → Tag |
| `IndicatorType` | 8 | **TypeID**, Code, Name |
| `Malware` | 842 | **MalwareID**, ExternalID, Name, MalwareTypeID → MalwareType, Description, Platforms, CreatedAt, UpdatedAt |
| `MalwareAlias` | 284 | **MalwareID** → Malware, **Alias** |
| `MalwareIndicator` | 1,446 | **MalwareID** → Malware, **IndicatorID** → Indicator, Role, Confidence, EvidenceID → Evidence |
| `MalwareTechnique` | 11,608 | **MalwareID** → Malware, **TechniqueID** → Technique, Confidence, EvidenceID → Evidence |
| `MalwareType` | 12 | **MalwareTypeID**, Code, Name |
| `MalwareVulnerability` | 11 | **MalwareID** → Malware, **VulnerabilityID** → Vulnerability, Confidence, EvidenceID → Evidence |
| `Motivation` | 5 | **MotivationID**, Name |
| `Role` | 3 | **RoleID**, Code, Name |
| `Sector` | 14 | **SectorID**, Name |
| `SeverityLevel` | 5 | **SeverityID**, Code, Name, Weight |
| `Sighting` | 286 | **SightingID**, IndicatorID → Indicator, SightedAt, Quantity, Location, Note, ReportedBy → AppUser |
| `Source` | 8 | **SourceID**, Name, Url, Reliability, Description, IsActive |
| `Tactic` | 15 | **TacticID**, ExternalID, ShortName, Name, Description, DisplayOrder |
| `Tag` | 13 | **TagID**, Name |
| `Technique` | 706 | **TechniqueID**, ExternalID, Name, Description, ParentTechniqueID → Technique |
| `TechniqueTactic` | 881 | **TechniqueID** → Technique, **TacticID** → Tactic |
| `ThreatActor` | 178 | **ActorID**, ExternalID, Name, Description, MotivationID → Motivation, CountryCode → Country, FirstSeen, LastSeen, IsActive, CreatedAt, UpdatedAt |
| `TLPLevel` | 4 | **TLPID**, Code, Description |
| `UserSession` | 6 | **Token**, UserID → AppUser, CreatedAt, ExpiresAt |
| `Vulnerability` | 12 | **VulnerabilityID**, CveID, Title, Description, Vendor, Product, CvssScore, PublishedDate, IsKnownExploited |

## Graf düğüm tabloları (AS NODE) (6)

| Tablo | Satır | Kullanıcı sütunları |
|---|---:|---|
| `ActorNode` | 178 | ActorID |
| `CampaignNode` | 57 | CampaignID |
| `IndicatorNode` | 1,446 | IndicatorID |
| `MalwareNode` | 842 | MalwareID |
| `TechniqueNode` | 706 | TechniqueID |
| `VulnerabilityNode` | 12 | VulnerabilityID |

## Graf kenar tabloları (AS EDGE) (10)

| Tablo | Satır | Kullanıcı sütunları |
|---|---:|---|
| `ActorSharesToolsWith` | 898 | SharedCount |
| `ActorUsesMalware` | 1,166 | Confidence, EvidenceID, CreatedAt |
| `ActorUsesTechnique` | 4,815 | Confidence, EvidenceID, CreatedAt |
| `CampaignAttributedToActor` | 25 | Confidence, EvidenceID, CreatedAt |
| `CampaignContainsIndicator` | 232 | Confidence, EvidenceID, CreatedAt |
| `CampaignUsesMalware` | 173 | Confidence, EvidenceID, CreatedAt |
| `CampaignUsesTechnique` | 1,213 | Confidence, EvidenceID, CreatedAt |
| `IndicatesMalware` | 1,446 | Role, Confidence, EvidenceID, CreatedAt |
| `MalwareExploitsVulnerability` | 11 | Confidence, EvidenceID, CreatedAt |
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
| `MalwareExploitsVulnerability` | MalwareNode → VulnerabilityNode | CASCADE |
| `MalwareUsesTechnique` | MalwareNode → TechniqueNode | CASCADE |

## Görünümler (8)

`vw_ActorSummary`, `vw_CampaignSummary`, `vw_GraphEdge`, `vw_GraphNode`, `vw_Indicator`, `vw_IndicatorAttribution`, `vw_MalwareSummary`, `vw_SourceHealth`

## Saklı yordamlar (15)

`sp_ActorShortestPath`, `sp_AddSighting`, `sp_AttackMatrix`, `sp_BulkImportIndicators`, `sp_CheckGraphConsistency`, `sp_ExpireIndicators`, `sp_FinishImportJob`, `sp_GetNeighborhood`, `sp_GlobalSearch`, `sp_ImportAttackBundle`, `sp_IndicatorKillChain`, `sp_RefreshActorSimilarity`, `sp_SaveIndicator`, `sp_StartImportJob`, `sp_SyncGraph`

## Skaler fonksiyonlar (2)

`fn_IsValidIndicator`, `fn_RiskScore`

## Satır içi tablo değerli fonksiyonlar (1)

`fn_ActorTechniques`

## Tetikleyiciler (23)

`trg_ActorMalware_GraphEdge`, `trg_ActorTechnique_GraphEdge`, `trg_AppUser_Audit`, `trg_AuditLog_Protect`, `trg_Campaign_Audit`, `trg_Campaign_GraphAttribution`, `trg_Campaign_GraphNode`, `trg_CampaignIndicator_GraphEdge`, `trg_CampaignMalware_GraphEdge`, `trg_CampaignTechnique_GraphEdge`, `trg_Indicator_Audit`, `trg_Indicator_GraphNode`, `trg_Malware_Audit`, `trg_Malware_GraphNode`, `trg_MalwareIndicator_GraphEdge`, `trg_MalwareTechnique_GraphEdge`, `trg_MalwareVulnerability_GraphEdge`, `trg_Sighting_AfterInsert`, `trg_Technique_GraphNode`, `trg_Technique_Hierarchy`, `trg_ThreatActor_Audit`, `trg_ThreatActor_GraphNode`, `trg_Vulnerability_GraphNode`

## Kısıt ve indeks sayıları

CHECK: 30 · FOREIGN KEY: 54 · UNIQUE: 25 · DEFAULT: 43 · İndeks (PK dahil): 127

## Veritabanı rolleri

| Rol | GRANT | DENY |
|---|---:|---:|
| `tip_admin` | 7 | 0 |
| `tip_analyst` | 57 | 0 |
| `tip_reader` | 7 | 5 |
