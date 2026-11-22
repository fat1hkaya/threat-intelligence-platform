# ThreatLens: Proje, gereksinimler ve mimari

> Teknik başvuru belgesidir. Ders raporlarının metni ekip tarafından özgün olarak yazılmalıdır; buradaki bilgiler (tablo adları, sayılar, sorgular) rapora kaynak olarak kullanılabilir.

## 1. Amaç ve kapsam

ThreatLens, bir SOC analistinin bir IOC'yi (IP, domain, URL, MD5/SHA-1/SHA-256, e-posta) araştırırken sorduğu soruları tek veritabanından yanıtlar:

- Bu değer kayıtlı mı, ne kadar güvenilir, en son ne zaman görüldü?
- Hangi zararlı yazılım ailesiyle ilişkili? O aile hangi kampanyalarda, hangi tehdit aktörlerince kullanıldı?
- Bu aktör hangi MITRE ATT&CK tekniklerini kullanıyor? İki aktör arasında ortak araç zinciri var mı?
- Bu ilişkiyi **kim, hangi kanıta dayanarak** kurdu?

Kapsam dışı: zararlı dosyaların kendisi (yalnızca metadata), otomatik engelleme, SIEM entegrasyonu.

## 2. Gereksinimler

### İşlevsel

| No | Gereksinim | Karşılandığı yer |
|---|---|---|
| G1 | IOC ekleme, düzenleme, silme; türüne göre doğrulama ve normalleştirme | `app/services/normalize.py`, `sp_SaveIndicator`, `fn_IsValidIndicator` |
| G2 | Aynı IOC'nin farklı yazımlarla tekrar eklenmemesi | `UQ_Indicator_Type_Normalized (TypeID, NormalizedValue)` |
| G3 | IOC arama, filtreleme (tip, önem, kaynak, güven aralığı, tarih), sıralama, sayfalama | `GET /api/iocs`, `vw_Indicator` |
| G4 | IOC → zararlı → kampanya → aktör → teknik ilişkilerinin graf olarak gösterimi | SQL Graph tabloları, `vw_GraphEdge`, `sp_GetNeighborhood`, İlişki grafı ekranı |
| G5 | Her ilişkinin kanıtı ve kaynağı | `Evidence` tablosu; kenar detay paneli |
| G6 | Aktörler arası en kısa yol | `sp_ActorShortestPath` (`SHORTEST_PATH`) |
| G7 | MITRE ATT&CK, abuse.ch ve CISA KEV'den içe aktarma; tekrar kaydı engelleme; iş özeti | `importers/`, `ImportJob`, `ImportJobError`, `sp_BulkImportIndicators` |
| G8 | Hatalı dosyada güvenli geri alma | Katı mod: `sp_BulkImportIndicators @Strict = 1` → ROLLBACK |
| G9 | Değişikliklerin denetimi | `trg_*_Audit` tetikleyicileri, `AuditLog`, `trg_AuditLog_Protect` |
| G10 | Rol tabanlı yetki (Yönetici, Analist, İzleyici) | `app/security.py` + `tip_reader ⊂ tip_analyst ⊂ tip_admin` |

### İşlevsel olmayan

- Tek bilgisayarda çalışma (SQL Server + Python, Docker/Redis yok); internet olmadan sunum (kütüphaneler `app/static/vendor/` altında).
- Tüm sorgular parametreli; ORM yok.
- Erişilebilirlik: semantik HTML, klavye gezinimi, görünür odak, renk yanında şekil/metin, grafiklerin metin özetleri, grafın tablo karşılığı.
- Duyarlı tasarım: 1440 / 1024 / 390 px.

## 3. Mimari

```
Tarayıcı (Jinja2 + saf JS, vis-network, Chart.js)
   │  fetch /api/...   (oturum çerezi, X-Trace-Id başlığı)
FastAPI (app/api/*.py)  ── parametreli T-SQL ──►  pyodbc / ODBC Driver 18
   │                                                    │
   └─ services/normalize.py, importer.py               SQL Server: ThreatLens
                                                         ├─ İlişkisel tablolar (asıl kaynak)
                                                         ├─ SQL Graph (AS NODE / AS EDGE)
                                                         ├─ görünüm, fonksiyon, yordam
                                                         └─ tetikleyiciler (denetim + graf eşleme)
```

- **Kimlik:** PBKDF2-SHA256 parola özeti, `UserSession` tablosunda oturum anahtarı, HttpOnly çerez. Her istekte `sp_set_session_context 'user_id'` çağrılır; tetikleyiciler değişikliği yapan kullanıcıyı buradan okur.
- **SQL izi:** `app/db.py` her isteğin çalıştırdığı SQL'i bellekte tutar. Arayüzdeki "SQL" çekmecesi `GET /api/trace/{id}` ile gösterir.
- **Hata eşleme:** T-SQL `THROW 50001–50099` → HTTP 400 (Türkçe mesaj), 2601/2627 → 409, 547 → 400/409.

## 4. İlişkisel model

38 ilişkisel tablo vardır. Tam liste için `docs/veritabani_nesneleri.md` dosyasına bakın (sistem kataloğundan üretilir).

| Grup | Tablolar |
|---|---|
| Sözlük | `Role`, `IndicatorType`, `SeverityLevel`, `TLPLevel`, `Country`, `Sector`, `Motivation`, `MalwareType`, `Source`, `Tag` |
| Kullanıcı | `AppUser`, `UserSession` |
| ATT&CK | `Tactic`, `Technique` (özyinelemeli `ParentTechniqueID`), `TechniqueTactic` |
| Çekirdek | `ThreatActor` (+`ActorAlias`), `Malware` (+`MalwareAlias`), `Campaign`, `Vulnerability`, `Indicator`, `Sighting`, `Evidence` |
| M:N ilişkiler | `ActorMalware`, `ActorTechnique`, `MalwareTechnique`, `MalwareVulnerability`, `MalwareIndicator` (+`Role`), `CampaignMalware`, `CampaignTechnique`, `CampaignIndicator`, `IndicatorTag`, `ActorTargetSector`, `ActorTargetCountry` |
| İşletim | `ImportJob`, `ImportJobError`, `AuditLog` |

Tasarım kararları:
- Her M:N ilişki satırı isteğe bağlı `Confidence` ve `EvidenceID` taşır. Kaynak, kanıt üzerinden bilinir; ilişki tablolarında ayrıca `SourceID` tutulmaz (geçişli bağımlılık olmasın diye).
- **Bilinçli türetilmiş nitelik:** `Indicator.NormalizedValue`, `Value`'nun fonksiyonudur. Tekrar kaydı önleyen benzersizlik kısıtı için saklanır.
- **Hesaplanan, saklanmayan nitelikler:** risk skoru (`fn_RiskScore`), görülme sayısı, ilişki sayıları (görünümler).
- **İyimser eşzamanlılık:** `Indicator.RowVer ROWVERSION`.
- Kısıt sayıları: CHECK, FK, UNIQUE, DEFAULT. Güncel değerler `docs/veritabani_nesneleri.md` dosyasında.

Diyagramlar: `docs/diyagramlar/chen_er.dot` (Chen gösterimi) ve `docs/diyagramlar/iliskisel_sema.md` (Mermaid).

## 5. SQL Graph katmanı

| Düğüm (AS NODE) | Kenar (AS EDGE) | Kenar kısıtı |
|---|---|---|
| `IndicatorNode` | `IndicatesMalware` (+Role) | IndicatorNode → MalwareNode |
| `MalwareNode` | `ActorUsesMalware` | ActorNode → MalwareNode |
| `ActorNode` | `ActorUsesTechnique` | ActorNode → TechniqueNode |
| `CampaignNode` | `MalwareUsesTechnique` | MalwareNode → TechniqueNode |
| `TechniqueNode` | `MalwareExploitsVulnerability` | MalwareNode → VulnerabilityNode |
| `VulnerabilityNode` | `CampaignAttributedToActor` | CampaignNode → ActorNode |
| | `CampaignUsesMalware` | CampaignNode → MalwareNode |
| | `CampaignUsesTechnique` | CampaignNode → TechniqueNode |
| | `CampaignContainsIndicator` | CampaignNode → IndicatorNode |
| | `ActorSharesToolsWith` (türetilmiş, ≥3 ortak araç) | ActorNode → ActorNode |

Şartnamedeki adlarla eşleşme: IOCNode = `IndicatorNode`, IOCAssociatedWithMalware = `IndicatesMalware`, MalwareUsedInCampaign = `CampaignUsesMalware` (yön kampanyadan zararlıya), CampaignContainsIOC = `CampaignContainsIndicator`.

- **1:1 eşleme:** Her düğüm, ilişkisel kaydının anahtarını `UNIQUE` olarak taşır. Ad, açıklama gibi nitelikler tekrar edilmez; `vw_GraphNode` ile birleştirilir.
- **Kenar kısıtları** (`CONNECTION … ON DELETE CASCADE`): yanlış tipte iki düğüm bağlanamaz, düğüm silinince kenarlar da silinir. `$from_id, $to_id` üzerinde UNIQUE, `$to_id` üzerinde ayrıca indeks vardır.
- **Tutarlılık:** Her ilişkisel tabloda eşleme tetikleyicisi bulunur (`trg_<Tablo>_GraphNode`, `trg_<Tablo>_GraphEdge`). Graf, ilişkisel değişiklikle **aynı transaction** içinde güncellenir; ROLLBACK grafı da geri alır (testle doğrulandı). `sp_SyncGraph` grafı baştan kurar; `sp_CheckGraphConsistency` iki modeli satır sayısıyla karşılaştırır.
- **MATCH yalnızca SELECT içinde** kullanılabildiği için silme ve güncellemeler `$node_id = $from_id` karşılaştırmasıyla yapılır. `sp_SyncGraph` önce mevcut kenarları MATCH ile `#cur` geçici tablosuna okur.
- **MATCH kullanan nesneler:** `vw_GraphEdge`, `vw_IndicatorAttribution`, `sp_IndicatorKillChain` (`i-(e1)->m<-(e2)-a-(e3)->t`), `GET /api/iocs/{id}/relationships` (IOC → zararlı → teknik), demo 2 ve 7.
- **SHORTEST_PATH:** `sp_ActorShortestPath` yalnızca ağırlıksız en kısa yolu bulur. `SharedCount` veya güven puanı ağırlık olarak kullanılmaz; birden çok en kısa yol varsa biri döner.

Doğrulanan davranışlar (SQL Server 2025, 15 Kasım 2026):
- MATCH görünüm içinde çalışıyor.
- Aynı FROM'da düğüm/kenar tablolarıyla sıradan tablolar birlikte kullanılabiliyor.
- `INSERT INTO #cur SELECT … MATCH` çalışıyor.
- `STRING_AGG(INT) WITHIN GROUP (GRAPH PATH)` çalışıyor.
- Tetikleyicideki kenar silme çalışıyor.

Kurulum sırasında karşılaşılan iki pratik sorun ve çözümü:
1. ODBC sürücüsü `{1,6}` gibi süslü parantezleri escape dizisi sanıyor. Çözüm: bağlantıda `SQL_ATTR_NOSCAN`.
2. Sunucu harmanlaması `Turkish_CI_AS` iken veritabanı `Latin1_General_100_CI_AS`. Çözüm: `#cur` sütunlarına `COLLATE DATABASE_DEFAULT`.

## 6. Programlanabilir nesneler

| Tür | Nesneler |
|---|---|
| Görünüm | `vw_Indicator`, `vw_ActorSummary`, `vw_MalwareSummary`, `vw_CampaignSummary`, `vw_GraphNode`, `vw_SourceHealth`, `vw_GraphEdge` (MATCH), `vw_IndicatorAttribution` (MATCH) |
| Fonksiyon | `fn_RiskScore` (skaler), `fn_IsValidIndicator` (skaler), `fn_ActorTechniques` (satır içi tablo değerli) |
| Yordam | `sp_SaveIndicator`, `sp_BulkImportIndicators`, `sp_StartImportJob`, `sp_FinishImportJob`, `sp_AddSighting`, `sp_ExpireIndicators`, `sp_GlobalSearch`, `sp_GetNeighborhood`, `sp_AttackMatrix`, `sp_ImportAttackBundle`, `sp_SyncGraph`, `sp_CheckGraphConsistency`, `sp_IndicatorKillChain`, `sp_ActorShortestPath`, `sp_RefreshActorSimilarity` |
| Tetikleyici | Denetim: `trg_Indicator/ThreatActor/Malware/Campaign/AppUser_Audit`. Koruma: `trg_AuditLog_Protect` (INSTEAD OF). İş kuralı: `trg_Sighting_AfterInsert`, `trg_Technique_Hierarchy`. Graf eşleme: 15 tetikleyici. |

Migration'larla (`database/migrations/10–20`) eklenen nesnelerin tam listesi canlı sistemden üretilen [veritabani_nesneleri.md](veritabani_nesneleri.md) dosyasındadır; özet için §10'a bakın.

Transaction örnekleri:
- `sp_SaveIndicator`: IOC + etiketler tek transaction. Eski RowVer ile güncelleme 50009 hatası verir.
- `sp_BulkImportIndicators`: yığın başına transaction. Katı modda ROLLBACK yapılır; hata kayıtları ROLLBACK'ten **sonra** yazılır, çünkü tablo değişkeni geri alınmaz.
- `POST /api/links`: önce `Evidence`, sonra ara tablo satırı yazılır, tetikleyiciyle kenar oluşur; hepsi tek transaction.

## 7. Güvenlik

- **Uygulama katmanı:** `require_analyst`, `require_admin` bağımlılıkları. İzleyici yazma denemesinde 403 alır.
- **Application Role:** oturum doğrulandıktan sonra bağlantı `sp_setapprole` ile kullanıcının rolüne (`app_viewer`, `app_analyst`, `app_admin`) indirgenir. Uygulama katmanındaki bir hata bile rolün GRANT/DENY sınırını aşamaz. Rol parolaları `.env` dosyasındaki `TL_APPROLE_SECRET` sırrından türetilir. `sp_setapprole` her çağrıda yaklaşık 150 ms sürdüğü için rol başına ayrı bağlantı havuzu tutulur; ODBC havuzu kapalıdır, çünkü rol etkin bağlantıyı bozar.
- **HTTP katmanı:** İçerik güvenlik politikası (betikler yalnızca sunucudan ve isteğe özel nonce'lu satır içi bloklardan), `X-Frame-Options: SAMEORIGIN`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`; API yanıtları `no-store`. Beklenmeyen hatalarda kullanıcı yalnızca kayıt kodu görür, ayrıntı `logs/app.log` dosyasındadır. `/api/docs` oturum ister.
- **Oturum ve giriş:** oturum belirteci veritabanında SHA-256 özetiyle saklanır (sızan tablo belirteç vermez). `LoginAttempt` + `fn_LoginLock`: 15 dakikada 5 hatalı deneme hesabı kilitler (429). Parola değişince diğer oturumlar kapanır.
- **Veritabanı katmanı** (`08_security.sql`):
  - `tip_reader` şemayı okur; `UserSession` ve `AppUser.PasswordHash` kolonu için DENY vardır.
  - `tip_analyst`, IOC ve ilişki tablolarına yazabilir ve içe aktarma yordamlarını çalıştırabilir.
  - `tip_admin`, kullanıcı ve kaynak tablolarına yazabilir.
  - `AuditLog` tablosuna INSERT/UPDATE/DELETE hiçbir role verilmez (DENY).
  - Testler `EXECUTE AS USER` ile 229 (izin yok) ve 230 (kolon DENY) hatalarını doğrular.
- **SQL enjeksiyonu:** kullanıcı girdisi yalnızca `?` parametresi olarak gider. Sıralama ve tablo adları izinli listeden seçilir.
- **XSS:** arayüz tüm dinamik metni kaçırır (`TL.esc`). Kanıt bağlantılarında yalnızca http(s) adreslerine izin verilir.

## 8. Veri kaynakları

| Kaynak | Güvenilirlik | Ne sağlar | Durum |
|---|---|---|---|
| MITRE ATT&CK Enterprise v20.1 (STIX 2.1) | A | Taktik, teknik, aktör, yazılım, kampanya ve aralarındaki 19.000 ilişki (açıklamalarıyla) | Yerel anlık görüntü, yüklü |
| abuse.ch ThreatFox / MalwareBazaar / URLhaus | B | IOC, hash, URL | Auth-Key gerekir |
| abuse.ch Feodo Tracker | B | Botnet C2 IP'leri | Anahtarsız, yüklü |
| CISA KEV | A | İstismar edilen zafiyetler | Anahtarsız, yüklü (1781 zafiyet) |
| Malpedia (Fraunhofer FKIE) | B | Zararlı ailesi diğer adları ve aile → aktör atıfları (CC BY-SA 4.0) | Anahtarsız, yüklü |
| iptoasn.com ip2asn-v4 | B | IPv4 aralığı → ASN ve ülke (Public Domain, PDDL v1.0) | Anahtarsız, yönetici yükler |
| Analist girişi | B | Elle veya dosyayla eklenenler | |

USOM'un zararlı bağlantı listesi değerlendirildi ama eklenmedi: `.txt` paylaşımı 1 Haziran 2026'da sona erdi; yerine gösterilen siberguvenlik.gov.tr API'sinin belgesi ve kullanım koşulları yayımlanmadı.

Beslemeler Windows Görev Zamanlayıcı ile 6 saatte bir, konsol penceresi açmadan senkronize edilir (`pythonw.exe scripts/sync_feeds.py`); geçici ağ hatalarında her besleme 3 kez denenir.

## 9. Performans

- Kapsayan indeksler (`IX_Indicator_LastSeen INCLUDE …`), filtreli indeks (`WHERE Status = 'active' AND ExpiresAt IS NOT NULL`), ara tablolarda ters yön indeksleri ve filtreli UNIQUE (`ExternalID`) kullanılır.
- Demo 5'te 500.000 satırlık tabloda indekssiz ve indeksli arama karşılaştırılır (`SET STATISTICS IO/TIME`). Öndeki joker karakter (`LIKE '%…'`) indeksin kullanılamadığı durumu gösterir.
- Tipik API yanıt süreleri (yerel, ATT&CK verisiyle, Kasım 2026 ölçümü): liste ekranları 10–35 ms, teknik listesi ~80–330 ms, graf komşuluğu ~30 ms.

## 10. İleri özellikler (migration 10–20)

| # | Özellik | Veritabanı tarafı | Neden ilginç |
|---|---|---|---|
| 10–11 | IOC yaşam döngüsü | `RetentionPolicy` + `fn_LifetimeDays` (satır içi TVF), `sp_ExpireIndicators`, `sp_GraphMaintenance`, `MaintenanceRun`; SQL Server Agent işleri (her gece 02:00, pazar 03:00) | Süresi dolan IOC'ler sunucu içinde, uygulamadan bağımsız olarak kapanır; görülme tetikleyicisi süreyi uzatır |
| 12 | Zararlı ailesi adı | `fn_NameKey` (SCHEMABINDING, kalıcı hesaplanmış sütun + indeks), `fn_FindMalware`, `sp_MergeMalware`, `sp_ImportMalpedia` | "Cobalt Strike", "CobaltStrike", "cobalt_strike" tek aileye düşer; birleştirmede ilişkiler ve graf kenarları taşınır |
| 13 | Kimlik doğrulama | `LoginAttempt`, `fn_LoginLock`, `sp_EndUserSessions`, Application Role | Bkz. §7 |
| 3 | Açıklanabilir risk skoru | `fn_RiskBreakdown` (satır içi TVF): bileşenleri ayrı sütunlar; `fn_RiskScore` ondan türer | Skor sorgu planına gömülür (skaler UDF maliyeti yok), arayüz her bileşeni gösterir |
| 14 | Log avı (retro-hunt) | `HuntRun`, `HuntMatch`, `sp_RetroHunt` | Binlerce aday tek set tabanlı sorguda birebir / URL ana bilgisayarı / üst domain olarak eşlenir |
| 15 | Tespit kapsamı | `DetectionCoverage`, `fn_EffectiveCoverage` (üst teknikten devralma), `sp_ActorCoverage`, `sp_CoverageOverview` | **İlişkisel bölme** (çift `NOT EXISTS`): tüm teknikleri kapsanan aktörler |
| 16 | Temporal tablolar | `Indicator`, `MalwareIndicator` (`SYSTEM_VERSIONING`, 90 gün, gizli dönem sütunları) | `FOR SYSTEM_TIME AS OF`: "bu IOC geçen salı ne durumdaydı?" |
| 17 | Performans | `vw_IndicatorCounts` indexed view (`WITH NOEXPAND`; Standard sürüm otomatik eşlemez), `AuditLog` columnstore, Query Store + `sp_TopQueries` | Gösterge paneli sayaçları birkaç önceden toplanmış satırdan okunur |
| 18 | Tam metin arama | `FREETEXTTABLE` / `CONTAINS`, `sp_TextSearch`; kurulu değilse LIKE | Kelime biçimleri ve alaka sıralaması |
| 19 | Vakalar | `Investigation`, `InvestigationNote`, `InvestigationNode` (AS NODE), `InvestigationIncludes` (AS EDGE, 6 bağlantı türü, ON DELETE CASCADE), `vw_InvestigationItem` (MATCH) | Çok biçimli ilişki ("vaka herhangi bir varlığı içerebilir") yabancı anahtarsız EntityType/EntityID anti-deseni yerine tür güvenli tek kenar tablosuyla çözülür |
| 21 | Bakım | SIMPLE kurtarma modeli, `sp_BackupDatabase` (gecelik, sıkıştırılmış, `RESTORE VERIFYONLY` ile doğrulanmış, haftanın günü başına dönen 7 dosya), `sp_CheckIntegrity` (haftalık DBCC CHECKDB) | Log yedeği alınmayan FULL modelde log dosyası sınırsız büyüyordu (3,9 GB) |
| 22 | Ayarlama | 22 yabancı anahtar indeksi (çoğu filtreli), `sp_PurgeHistory` (haftalık), READ_COMMITTED_SNAPSHOT | Kanıt silmek 9 tabloyu taramıyor; içe aktarma sürerken okumalar bloklanmıyor |
| 20 | Ağ zenginleştirme | `AutonomousSystem`, `IpRange`, `IndicatorNetwork` (1:1), `fn_Ipv4ToBigint`, `sp_EnrichNetwork`, `trg_Indicator_Network`, `sp_InfrastructureOverlap` | Aralık araması `BETWEEN` yerine `TOP (1) ... WHERE StartIP <= ip ORDER BY StartIP DESC` ile tek indeks araması; /24 kümeleri paylaşılan altyapıyı gösterir |

Dışa aktarma (`app/api/exports.py`): STIX 2.1 paketleri (IOC, aktör, vaka = `grouping`, notlar = `note`, graf kenarları = `relationship`, TLP işaretlemesi, belirlenimci `uuid5` kimlikleri) ve MITRE ATT&CK Navigator katmanları (aktör teknikleri, kapsama renkleri).
