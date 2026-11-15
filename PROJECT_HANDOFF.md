# GÜNCEL DURUM — 15 Kasım 2026 (önce bunu okuyun)

**Proje çalışır durumda ve tamamlandı.** Aşağıdaki eski bölümler (§1–§11) tarihsel kayıttır; "yapılacak" diye geçen maddelerin hepsi bu oturumda yapıldı.

Çalıştırma: `README.md`. Kısaca:
1. `.venv\Scripts\python scripts\setup_db.py`
2. `.venv\Scripts\python run.py`
3. http://127.0.0.1:8000 adresini açın; kullanıcı `fatih` / `ThreatLens2026!`.

**Ortam (bu bilgisayar):** SQL Server **2025 Developer** 17.0.1000.7, varsayılan örnek MSSQLSERVER, Windows kimlik doğrulama, sysadmin = NULLTRACEXatih. SQL Server 2022 web yükleyicisi Microsoft tarafından emekliye ayrıldığı için 2025 kuruldu. Ayrıca ODBC Driver 18, sqlcmd ve `.venv` (Python 3.14) kurulu.

**Yapılanlar (hepsi gerçek sunucuda çalıştırıldı):**
- **Veritabanı:**
  - 01–09 SQL dosyaları sıfırdan kurulumda hatasız çalışıyor (`--reset` ile doğrulandı, ≈20 sn).
  - ATT&CK v20.1 (19.000 kanıtlı ilişki) ve DEMO DATA (1446 IOC) yüklü; graf tutarlı.
  - §5.3'teki 5 graf varsayımının **5'i de doğrulandı**.
  - Düzeltmeler:
    - ODBC escape taraması kapatıldı (`SQL_ATTR_NOSCAN`).
    - `#cur` harmanlaması düzeltildi.
    - `trg_AppUser_Audit` eklendi.
    - Demo 5'teki PK hatası giderildi.
    - Yedekleme betiği taşınabilir yollara geçirildi.
- **Backend:**
  - `app/api/` şartnamedeki uçlarla yeniden yazıldı: `dashboard`, `iocs`, `graph`, `attack`, `entities`, `admin`, `auth`.
  - `config.py` ROOT hatası, `setup_db.py` ve `importers/demo_data.py` düzeltildi/yazıldı.
- **Arayüz** (Jinja2 + saf JS): 11 ekran + giriş sayfası.
  - SQL çekmecesi, global arama (Ctrl+K), vis-network graf (kenar kanıtı, genişletme, SHORTEST_PATH), Chart.js grafikleri.
  - Duyarlı tasarım (1440/1024/390 px tarandı, JS hatası ve yatay taşma yok).
  - Kütüphaneler `app/static/vendor/` altında; çevrimdışı çalışır.
- **Testler:** `pytest` → **79/79 geçti** (normalleştirme, API, rol yetkileri, eşzamanlılık, ROLLBACK, graf, demo betikleri, yedekleme, GRANT/DENY).
- **Belgeler:** `README.md`, `docs/01_proje_ve_mimari.md`, `docs/02_normalizasyon_taslak.md` (5 örnek, 4 adım, sorgular doğrulandı; **ekip özgün metne çevirmeli**), `docs/03_test_ve_demo.md`, `docs/diyagramlar/` (Chen ER .dot, Mermaid şema), `docs/api.md` ve `docs/veritabani_nesneleri.md` (`scripts/gen_docs.py` ile üretilir).
- **Git:** yerel depo açıldı ve ilk commit atıldı. GitHub'a gönderilmedi; uzak depo yok.

**Açık kalanlar:**
1. GitHub deposu oluşturup push etmek: `gh` kurulu değil, web arayüzünden depo açıp `git remote add origin …` ve `git push -u origin main` komutlarını çalıştırın.
2. abuse.ch anahtarı alıp canlı beslemeleri denemek; canlı istekler hiç yapılmadı.
3. Raporlar için ekran görüntüleri ve draw.io ile Chen ER çizimi (ekip derste bu formatı kullanıyor; `.dot` dosyası referans).
4. Ekran okuyucuyla erişilebilirlik denemesi yapılmadı.
5. Test çalıştırmak veritabanına denetim/iş kaydı ekler (tasarım gereği silinemez). Sunum öncesi temiz veri için `setup_db.py --reset` kullanın.

---

# ThreatLens — Proje Devir Belgesi (PROJECT_HANDOFF)

> Son güncelleme: 15 Kasım 2026, 11:40 (İstanbul). Hazırlayan: Claude (claude.ai bulut oturumu).
> Bu belge, geliştirmeyi Claude Code'da devralacak kişi/ajan içindir. **Önce bu belgeyi baştan sona okuyun.**

---

## 0. Kısa özet (TL;DR)

- **Proje:** ThreatLens — BLM3001 Veri Tabanı Yönetim Sistemleri dersi için MSSQL + SQL Graph tabanlı Tehdit İstihbaratı Platformu (TIP). 3 kişilik grup, sahibi Fatih Kaya.
- **Durum:** Veritabanı katmanı (SQL dosyaları) büyük ölçüde yazıldı ama **hiçbir SQL dosyası henüz gerçek bir SQL Server'da çalıştırılmadı** (bulut ortamında SQL Server kurulamadı). Python servis katmanı (normalleştirme, içe aktarma) yazıldı ve birim testleri geçiyor. **FastAPI uç noktaları yeni şemaya henüz uyarlanmadı** (eski adlar kullanılıyor, şu an çalışmaz). **Arayüz (Jinja2 + vanilla JS) henüz yazılmadı**; eski React prototipi `_archive/` içinde referans olarak duruyor.
- **İlk yapılacak iş:** Windows'ta SQL Server 2022 üzerinde `database/` betiklerini sırayla çalıştırıp hataları düzeltmek (bkz. §9, Adım 1).

---

## 1. Konumlar

| Ne | Yol |
|---|---|
| Projenin kalıcı yeri (kullanıcının bilgisayarı) | `C:\Users\fatih\Github\threat-intelligence-platform` |
| Geliştirildiği geçici bulut kopyası (artık kullanılmayacak) | `/home/claude/tip` (bulut oturumu kapanınca silinir) |
| Tasarım görselleri | `docs/design-references/*.png` (aşağıdaki tablo) |
| Şartname (kullanıcının verdiği ana talimat metni) | `docs/design-references/SARTNAME_ThreatLens_prompt.txt` |
| Eski React prototipi (kullanılmıyor, sayfa mantığı ve metinler için referans) | `_archive/react-prototype/src/` |
| Eski demo veri üreteci (yeni `importers/demo_data.py` için kaynak) | `_archive/seed_demo_eski.py` |
| `05_graph.sql`'i üreten betik ve parçaları | `_archive/gen_graph/` |

**Git:** Klasörde henüz git deposu yok. GitHub'da depo açılmadı (bulut oturumunda GitHub kimlik bilgisi yoktu). Kullanıcı bilgisayarında `git init` + `gh repo create` yapılmalı (§9, Adım 0). Hocanın kuralı: proje GitHub'dan paylaşılacak, düzenli commit atılmalı.

### Tasarım görselleri

| Dosya | İçerik |
|---|---|
| `00_konsept_akis.png` | Konsept: SHA-256 → Malware Family → Campaign / ATT&CK → Threat Actor akışı, renk paleti |
| `genel_bakis_graf_ioc_mobil_1.png` | Genel Bakış, İlişki Grafi, IOC Araştırma + IOC detay paneli, mobil IOC listesi |
| `genel_bakis_graf_ioc_mobil_2.png` | Aynı ekranların ikinci varyantı (ilişki grafında kenar etiketleri, mobil genel bakış) |
| `genel_bakis_graf_ioc_mobil_3.png` | Üçüncü varyant (KPI kartlarında sparkline, "Son 30 günde eklenen IOC" grafiği) |
| `tehdit_aktorleri.png` | Aktör listesi + sağda Aktör Detayı paneli |
| `kampanyalar.png` | Kampanya listesi + sağda Kampanya Detayı paneli, zaman çizelgesi, hedef sektörler |
| `mitre_attack.png` | Taktik kartları, teknik tablosu, sağda Teknik Detayı paneli |
| `veri_kaynaklari.png` | Kaynak tablosu, içe aktarma iş geçmişi, sağda Kaynak Yapılandırması paneli |
| `denetim_kayitlari.png` | Denetim kaydı tablosu, günlük olay grafiği, sağda Olay Detayı (önceki/yeni değer) |
| `ayarlar.png` | Ayarlar: rol yetki matrisi, risk eşikleri, entegrasyonlar |

**Kullanıcının tasarım istekleri:** Görseller genel çizgiyi verir, birebir kopya istenmiyor ("daha iyi rötuşlarla daha iyi hale getirebilirsin"). Üst barda kullanıcı adı **"Fatih Kaya"** olacak (görsellerdeki "Derya Kaya" değil). Tasarım **responsive** olmalı (1440 / 1024 / 390 px). Uygulama dili Türkçe; ATT&CK kodları ve yaygın güvenlik terimleri İngilizce kalabilir.

**Görsellerdeki sahte özellikleri kopyalamayın:** MFA, e-posta bildirimleri, API anahtarı yönetimi gibi arka planı olmayan anahtarlar (toggle) eklenmemeli. Görsellerdeki "+%6,8" gibi değişim yüzdeleri gerçek sorgularla hesaplanmalı ya da gösterilmemeli. Şartname: "Dashboard üzerindeki tüm istatistikleri MSSQL üzerinden gerçek sorgularla üret."

---

## 2. Ders kuralları (hocanın istedikleri ve yasakları)

Kaynak: BLM3001 laboratuvar slaytları (Doç. Dr. Buket Doğan, Arş. Gör. Dr. Büşra Büyüktanır, Arş. Gör. Semiha Koç).

- İlişkisel veri tabanı modeli. VTYS serbest; **MSSQL seçildi**.
- **ORM yasak** (Entity Framework, SQLAlchemy ORM vb.). Tüm veritabanı işlemleri doğrudan SQL. Bu projede `pyodbc` + elle yazılmış parametreli T-SQL kullanılıyor.
- Arayüzde yapay zekâ kullanımı serbest; SQL'in kendisi ORM'siz olmalı.
- Proje GitHub'dan paylaşılır. Raporlar Google Classroom'a yüklenir.
- Değerlendirme: tablo sayısı, normalizasyon, DDL/DML sorgularının kapsamı ve doğruluğu, arayüz, raporlar.
- Takvim: Ödev 2 / Ara Rapor 1 → 12 Kasım (geçti), **Ödev 3 / Ara Rapor 2 → 26 Kasım** (normalizasyon; **en az 5 örnek**, her biri 4 adım: bağımlılıkları yaz → ihlali örnek veriyle göster → ayrıştır → kayıpsızlığı doğrula), final raporu + sunum **17–31 Aralık**.
- Kopya cezası −500 puan. Raporlar ekip tarafından özgün yazılmalı; Claude taslak/iskele verebilir ama teslim edilecek metni "yapay zekâ yazmamış gibi" görünecek şekilde üretmez.

---

## 3. Teknoloji yığını (şartnameye göre)

- Veritabanı: **SQL Server 2022 Developer** (en az 2019: kenar kısıtı ve `SHORTEST_PATH` gerektirir), T-SQL.
- Backend: Python 3.12+, **FastAPI**, **pyodbc** (ORM yok).
- Frontend: **Jinja2 + HTML5 + CSS3 + vanilla JavaScript**, **vis-network** (graf), **Chart.js** (grafikler), **Lucide** (ikonlar), **Inter** ve **JetBrains Mono** yazı tipleri. Çevrimdışı sunum için kütüphaneler `app/static/vendor/` altına yerel kopyalanmalı (CDN'e bağımlı olmasın).
- Test: pytest. Yapılandırma: `.env` (örnek: `.env.example`).
- React, Next.js, Redis, Celery, Docker zorunlu değilse eklenmeyecek.

> **Not:** İlk gün React + Vite ile bir arayüz yazılmaya başlandı. Kullanıcı şartnameyi verince Jinja2 + vanilla JS'e geçildi. React kodu `_archive/react-prototype/` altında; **çalıştırılmayacak**, yalnızca sayfa mantığı, Türkçe arayüz metinleri ve SQL çekmecesi fikri için referans.

---

## 4. Klasör yapısı (mevcut)

```
threat-intelligence-platform/
├─ PROJECT_HANDOFF.md          ← bu belge
├─ run.py                      ← uvicorn başlatıcı (GÜNCELLENMELİ, §6)
├─ requirements.txt            ← fastapi, uvicorn, pyodbc (jinja2, python-multipart, pytest EKLENMELİ)
├─ .env.example, .gitignore
├─ app/
│  ├─ main.py                  ← ESKİ (React dist servis ediyor) → Jinja2'ye çevrilecek
│  ├─ config.py                ← ESKİ ortam değişkeni adları (TIP_*, GozcuTIP) → TL_*, ThreatLens
│  ├─ db.py                    ← ham SQL erişim katmanı + sorgu izi (TRACES). Hazır.
│  ├─ security.py              ← PBKDF2 parola, oturum çerezi, rol denetimi. Çerez adı "gozcu_session" → değiştirilmeli
│  ├─ api/                     ← FastAPI uç noktaları. ESKİ ŞEMAYA GÖRE YAZILDI, uyarlanmalı (§6)
│  │  ├─ auth.py, overview.py, indicators.py, entities.py, admin.py
│  ├─ services/
│  │  ├─ normalize.py          ← IOC normalleştirme/doğrulama. HAZIR, test edildi.
│  │  └─ importer.py           ← CSV/JSON ayrıştırma + ImportJob hattı. HAZIR (DB'de denenmedi).
│  ├─ templates/               ← BOŞ (yapılacak)
│  └─ static/{css,js/pages,vendor,img}  ← BOŞ (yapılacak)
├─ database/                   ← kurulum sırası = dosya adındaki numara
│  ├─ schema/01_tables.sql
│  ├─ indexes/02_indexes.sql
│  ├─ functions/03_functions.sql
│  ├─ views/04_views.sql
│  ├─ graph/05_graph.sql       ← SQL Graph: AS NODE / AS EDGE, MATCH, SHORTEST_PATH, eşleme tetikleyicileri
│  ├─ procedures/06_procedures.sql
│  ├─ triggers/07_triggers.sql ← denetim (audit) tetikleyicileri
│  ├─ security/08_security.sql ← roller, GRANT/DENY
│  ├─ seed/09_lookups.sql      ← sözlük verileri
│  ├─ seed/attack_snapshot.json← MITRE ATT&CK v20.1 Enterprise sadeleştirilmiş (5,7 MB)
│  ├─ demos/                   ← 7 demo senaryosu + sample_queries.sql (kurulumda çalışmaz)
│  └─ backup/backup_restore.sql
├─ importers/
│  ├─ _db.py                   ← bağlantı, source_id, GO ile ayrılmış .sql çalıştırıcı
│  ├─ abusech.py               ← ThreatFox, MalwareBazaar, URLhaus, Feodo
│  ├─ cisa_kev.py              ← CISA KEV → Vulnerability (MERGE)
│  ├─ mitre_attack.py          ← anlık görüntüyü sp_ImportAttackBundle ile yükler
│  ├─ build_attack_snapshot.py ← STIX 2.1 → attack_snapshot.json
│  └─ __main__.py              ← `python -m importers <kaynak>` (demo_data.py'yi import ediyor, DOSYA YOK)
├─ scripts/setup_db.py         ← BOZUK: silinen _common ve seed_demo'yu import ediyor (§6)
├─ tests/
│  ├─ conftest.py
│  └─ test_normalize.py        ← 34 test, hepsi geçiyor
├─ docs/design-references/     ← tasarım görselleri + şartname
└─ _archive/                   ← referans; uygulama tarafından kullanılmaz
```

Şartnamedeki `app/repositories/` klasörü bilinçli olarak açılmadı: SQL sorguları ilgili uç nokta dosyasında duruyor ki sunumda "bu ekranın SQL'i şurada" diye gösterilebilsin. İstenirse ayrılabilir.

---

## 5. Veritabanı (MSSQL) — durum

**Veritabanı adı:** `ThreatLens` (collation `Latin1_General_100_CI_AS`).

### 5.1 İlişkisel tablolar (`schema/01_tables.sql`) — yazıldı, çalıştırılmadı

- Sözlük: `Role`, `IndicatorType` (ipv4, ipv6, domain, url, md5, sha1, sha256, email), `SeverityLevel` (info…critical, Weight), `TLPLevel`, `Country`, `Sector`, `Motivation`, `MalwareType`, `Source` (Reliability A–F, Admiralty ölçeği), `Tag`.
- Kullanıcı: `AppUser`, `UserSession`.
- Kanıt: **`Evidence`** (SourceID, Summary, Url, ExternalRef = STIX relationship id). İlişki tablolarında ayrıca SourceID tutulmaz (EvidenceID → SourceID geçişli bağımlılığı olmasın diye).
- ATT&CK: `Tactic`, `Technique` (ParentTechniqueID ile özyinelemeli alt teknik), `TechniqueTactic`.
- Çekirdek: `ThreatActor` (+`ActorAlias`), `Malware` (+`MalwareAlias`), `Campaign` (ActorID + AttributionEvidenceID), `Vulnerability`, **`Indicator`**, `Sighting`.
- `Indicator` önemli sütunlar: `Value` (gelen hâli), `NormalizedValue` (kanonik, **UNIQUE(TypeID, NormalizedValue)**), `Confidence` 0–100 CHECK, `Status` ('active','expired','revoked','false_positive'), `RowVer ROWVERSION` (iyimser eşzamanlılık). **`IsActive` sütunu kaldırıldı**; görünümde `Status='active'`tan türetiliyor.
- M:N ara tablolar (her birinde isteğe bağlı `Confidence` ve `EvidenceID`): `ActorMalware`, `ActorTechnique`, `MalwareTechnique`, `MalwareVulnerability`, `MalwareIndicator` (+`Role`: c2/payload/dropper/exfil/phishing/other), `CampaignMalware`, `CampaignTechnique`, `CampaignIndicator`, ayrıca `IndicatorTag`, `ActorTargetSector`, `ActorTargetCountry`.
- İşletim: **`ImportJob`** (eski adı IngestRun; JobType, IsStrict, RowsRead/Inserted/Updated/Skipped/Failed), **`ImportJobError`** (RowNo, RawValue, Reason), `AuditLog`.

### 5.2 Diğer nesneler

| Dosya | İçerik | Durum |
|---|---|---|
| `02_indexes.sql` | Kapsayan (INCLUDE), filtreli (`WHERE Status='active'`), ara tabloların ters yön indeksleri, filtreli UNIQUE (ExternalID) | yazıldı |
| `03_functions.sql` | `fn_RiskScore` (skaler, 0–100), `fn_IsValidIndicator` (skaler, biçim denetimi), `fn_ActorTechniques` (satır içi tablo değerli) | yazıldı |
| `04_views.sql` | `vw_Indicator` (Value = NormalizedValue, OriginalValue, IsActive, RowVer hex, RiskScore), `vw_ActorSummary`, `vw_MalwareSummary`, `vw_CampaignSummary`, `vw_GraphNode`, `vw_SourceHealth` (ImportJob'a göre) | yazıldı |
| `06_procedures.sql` | `sp_SaveIndicator` (yeni parametreler: `@NormalizedValue`, `@Status`, `@RowVer`; hata 50009 = eşzamanlı değişiklik), `sp_BulkImportIndicators` (`@JobID`, `@Strict`; katı modda gerçek ROLLBACK + hata kaydı), `sp_StartImportJob`, `sp_FinishImportJob`, `sp_AddSighting`, `sp_ExpireIndicators`, `sp_GlobalSearch`, `sp_GetNeighborhood` (kenarlarda Confidence/EvidenceID döner), `sp_AttackMatrix`, `sp_ImportAttackBundle` (her ATT&CK ilişkisi için Evidence kaydı) | yazıldı |
| `07_triggers.sql` | `trg_Indicator/ThreatActor/Malware/Campaign_Audit` (SESSION_CONTEXT('user_id'), `skip_audit` ile toplu yüklemede atlanır), `trg_Sighting_AfterInsert`, `trg_AuditLog_Protect` (INSTEAD OF, silme/güncelleme yasak), `trg_Technique_Hierarchy` | yazıldı |
| `08_security.sql` | Roller `tip_reader` ⊂ `tip_analyst` ⊂ `tip_admin`; GRANT/DENY; kolon düzeyi DENY (PasswordHash) | yazıldı |
| `09_lookups.sql` | Sözlükler + kaynaklar (MITRE ATT&CK, MalwareBazaar, ThreatFox, URLhaus, Feodo, CISA KEV, Analist girişi, **DEMO DATA**) | yazıldı |

Hata kodu kuralı: **50001–50099** iş kuralı ihlalleri; `app/db.py` bunları HTTP 400 ve Türkçe mesaj olarak döndürür.

### 5.3 SQL Graph (`graph/05_graph.sql`) — yazıldı, çalıştırılmadı

- Düğümler (`AS NODE`, yalnızca ilişkisel anahtarı UNIQUE taşır): `IndicatorNode`, `MalwareNode`, `ActorNode`, `CampaignNode`, `TechniqueNode`, `VulnerabilityNode`.
- Kenarlar (`AS EDGE`, her birinde **`CONNECTION (… TO …) ON DELETE CASCADE`** kenar kısıtı, `Confidence`, `EvidenceID`): `IndicatesMalware` (+Role), `ActorUsesMalware`, `ActorUsesTechnique`, `MalwareUsesTechnique`, `MalwareExploitsVulnerability`, `CampaignAttributedToActor`, `CampaignUsesMalware`, `CampaignUsesTechnique`, `CampaignContainsIndicator`, ve türetilmiş **`ActorSharesToolsWith`** (aktör→aktör, ≥3 ortak yazılım; SHORTEST_PATH için).
- Şartnamedeki adlarla eşleşme: IOCNode=IndicatorNode, IOCAssociatedWithMalware=IndicatesMalware, MalwareUsedInCampaign=CampaignUsesMalware (yön kampanyadan zararlıya), CampaignAttributedToActor, ActorUsesTechnique, MalwareUsesTechnique, CampaignContainsIOC=CampaignContainsIndicator.
- `$from_id, $to_id` için UNIQUE ve `$to_id` indeksleri.
- MATCH görünümleri: **`vw_GraphEdge`** (tüm kenarlar, MATCH ile), **`vw_IndicatorAttribution`** (gösterge → zararlı/kampanya → aktör; MATCH ile).
- Yordamlar: `sp_SyncGraph` (tüm grafı ilişkisel modelden yeniden kurar; MATCH ile mevcut kenarları `#cur`'a okur, değişiklikleri `$edge_id` üzerinden yapar), `sp_CheckGraphConsistency` (ilişkisel ve graf satır sayılarını karşılaştırır), `sp_RefreshActorSimilarity`, `sp_IndicatorKillChain` (çok adımlı MATCH: gösterge→zararlı←aktör→teknik), `sp_ActorShortestPath` (SHORTEST_PATH, ağırlıksız; Confidence ağırlık olarak KULLANILMAZ).
- **Eşleme tetikleyicileri:** Her ana tabloda `trg_<Tablo>_GraphNode` (AFTER INSERT, DELETE; `sp_settriggerorder` ile First) ve her ara tabloda `trg_<Tablo>_GraphEdge` (AFTER INSERT, UPDATE, DELETE); Campaign için `trg_Campaign_GraphAttribution`. Grafı ilişkisel değişiklikle **aynı transaction** içinde günceller; ROLLBACK grafı da geri alır.
- Tasarım kararı: Microsoft belgelerine göre **MATCH yalnızca SELECT içinde** destekleniyor. Bu yüzden DELETE/UPDATE işlemleri MATCH kullanmıyor; tetikleyiciler `$node_id = $from_id` karşılaştırmasıyla, eşitleme yordamı `#cur` geçici tablosuyla çalışıyor.
- Belgelerde açıkça yazmayan ve **ilk çalıştırmada doğrulanması gereken** varsayımlar:
  1. MATCH'in **görünüm (VIEW) içinde** kullanılabilmesi (`vw_GraphEdge`, `vw_IndicatorAttribution`). Çalışmazsa bunlar satır içi tablo değerli fonksiyona veya yordama çevrilmeli.
  2. Aynı FROM listesinde düğüm/kenar tablolarıyla **sıradan tabloların** (Malware, ThreatActor…) birlikte kullanılması (`sp_IndicatorKillChain`, demolar).
  3. `INSERT INTO #cur SELECT … WHERE MATCH(…)` biçimi.
  4. `STRING_AGG(a2.ActorID, ',') WITHIN GROUP (GRAPH PATH)` içinde INT sütun (örtük dönüşüm).
  5. Tetikleyicide `JOIN … ON a.$node_id = e.$from_id` ile kenar silme.
- `05_graph.sql` başlangıçta bir Python üreteciyle üretildi (`_archive/gen_graph/gen_graph.py`); artık doğrudan elle düzenlenebilir.

### 5.4 Demolar (`database/demos/`)

Şartnamedeki 7 demo için SSMS'te çalıştırılacak betikler yazıldı: `demo1_hash_investigation.sql`, `demo2_actor_techniques.sql`, `demo3_analyst_audit.sql`, `demo4_import_rollback.sql` (katı/esnek mod), `demo5_index_performance.sql` (500.000 satırlık geçici tablo, STATISTICS IO/TIME), `demo6_concurrency.sql` (iki pencere: kilit, READ UNCOMMITTED kirli okuma, rowversion ile kayıp güncelleme önleme), `demo7_graph_match.sql` (3 adımlı MATCH, ilişkisel karşılığı, SHORTEST_PATH, {1,2}). `sample_queries.sql`: S1–S23 (JOIN, anti-join, GROUP BY/HAVING, EXISTS, INTERSECT/EXCEPT, ilişkisel bölme, self join, RANK/PARTITION, kümülatif toplam, PIVOT, özyinelemeli CTE, UPDATE…FROM, TRY/CATCH, indeks, MATCH, SHORTEST_PATH, tutarlılık). `backup/backup_restore.sql`: BACKUP, VERIFYONLY, FILELISTONLY, farklı adla RESTORE … MOVE, satır kurtarma.

Demolardaki beklenen sonuçlar gerçek veritabanında **doğrulanmadı**.

### 5.5 Veri

- MITRE ATT&CK Enterprise **v20.1** anlık görüntüsü (`database/seed/attack_snapshot.json`): 15 taktik, 706 teknik, 178 aktör, 842 yazılım, 57 kampanya, 19.000 ilişki (actor_software 1166, actor_technique 4815, software_technique 11608, campaign_software 173, campaign_technique 1213, campaign_actor 25). 1103 ilişkinin ATT&CK'te açıklaması yok (genel kanıt metni kullanılır).
- Aktör köken ülkesi ve motivasyonu ATT&CK açıklamasının **ilk cümlesinden** anahtar sözcükle çıkarılıyor (78 aktöre ülke, 109'una motivasyon atandı; emin olunamayanlar NULL). Zararlı türü de açıklamadan çıkarılıyor. Raporda bu sezgisel yöntem belirtilmeli.
- ActorSharesToolsWith (≥3 ortak yazılım): 898 yönlü kenar, 67 aktör. Örnek en kısa yollar: APT29→FIN7 (1 adım), APT28→Lazarus (yol yok).
- **Henüz veritabanına hiç veri yüklenmedi.**

---

## 6. Backend (FastAPI) — durum

**Hazır ve güncel:** `app/db.py` (Db sınıfı, `query/one/scalar/execute/query_sets/transaction/set_user`, SQL Server hata kodlarını HTTP'ye çevirme, her isteğin SQL'ini `TRACES`'e kaydetme → arayüzde "Bu sayfanın SQL'i" çekmecesi için `GET /api/trace/{id}`), `app/security.py` (PBKDF2-SHA256, `require_analyst`, `require_admin`), `app/services/normalize.py`, `app/services/importer.py`.

**Eski şemaya göre yazılmış, uyarlanması gereken** (`app/api/*.py`, `app/main.py`, `app/config.py`, `run.py`, `scripts/setup_db.py`):

1. `app/main.py` hâlâ `from .routers import …` diyor → `from .api import …` olmalı. React `dist` servis ediyor → Jinja2 `TemplateResponse` + `StaticFiles("/static")` + sayfa rotaları (oturum yoksa `/login`'e yönlendir). Başlık "Gözcü TIP" → "ThreatLens".
2. `app/config.py`: `TIP_*` → `TL_*`, varsayılan veritabanı `GozcuTIP` → `ThreatLens`, `FRONTEND_DIST` kaldırılıp `TEMPLATES_DIR`, `STATIC_DIR` eklenmeli. `security.py` çerez adı `gozcu_session` → `tl_session`.
3. `vw_Indicator` artık `Value` = normalleştirilmiş değer döndürüyor; `IsActive` görünümde hâlâ var (türetilmiş). Ama **tablo** sorgularında `dbo.Indicator.IsActive` yok: `overview.py` satır ~32, 64, 73 (`i.IsActive = 1` → `i.Status = 'active'`), 108 (`i.Value` → `i.NormalizedValue`).
4. `indicators.py`: `sp_SaveIndicator` çağrısı yeni parametrelere (`@Value, @NormalizedValue, @Status, @RowVer`) geçmeli, `@IsActive` kaldırılmalı; normalleştirme `services.normalize` ile yapılmalı (hata → HTTP 400). Toplu sorgu (`/lookup`) `v.Value = j.[value]` → önce Python'da normalleştir. Pydantic modeline `status` ve `rowVer` ekle. Uç nokta yolları şartnameye göre `/api/iocs…` olmalı.
5. `admin.py`: `dbo.IngestRun` → `dbo.ImportJob` (sütunlar: RowsSkipped, RowsFailed, JobType, FileName, IsStrict); `/api/imports` (GET liste, POST dosya yükleme → `services.importer.parse_file` + `run_import`, GET `/api/imports/{id}` hata satırları) eklenmeli.
6. `entities.py`: ilişki ekleme (`POST /api/links`) Confidence ve kanıt metni alabilmeli (kanıt → önce `Evidence` satırı, sonra ara tablo). `actor-malware` değişince `EXEC dbo.sp_RefreshActorSimilarity`.
7. Yeni uç noktalar: `GET /api/graph/search?q=` (değeri düğüme çöz + komşuluk), `GET /api/graph/neighborhood?type&id&depth&limit`, `GET /api/graph/edge?...` (ilişki türü, güven, kanıt metni, kaynak, URL), `GET /api/graph/path?from&to` (sp_ActorShortestPath, aktör adlarıyla), `GET /api/iocs/{id}/relationships` (vw_IndicatorAttribution + sp_IndicatorKillChain), `GET /api/techniques` (filtreli liste + matris), `GET /api/audit-logs`, `GET /api/dashboard/summary`, `GET/POST /api/users` (admin).
8. `scripts/setup_db.py` bozuk: `_common` → `importers._db`; dosya listesi `database/*/0[1-9]_*.sql` sıralı olmalı (alt klasörler dahil, numaraya göre); kullanıcılar: **`fatih` (Fatih Kaya, admin)**, `analist`, `izleyici`; ardından `importers.mitre_attack.run`, `importers.demo_data.run`, `EXEC sp_CheckGraphConsistency` çıktısını yazdır. `--reset` dışında mevcut veritabanını **silmemeli**.
9. `importers/demo_data.py` yazılmalı (`_archive/seed_demo_eski.py`'den uyarlanacak): kaynak **"DEMO DATA"**, RFC 5737 IP'leri ve `.example/.test/.invalid` alan adları, rastgele özetler, her ilişkinin kanıt metni "DEMO DATA: sentetik ilişki" ile başlamalı; `run_import(..., job_type='demo')` kullanılmalı. Gerçek CVE–zararlı bağlantıları için kanıt kaynağı "Analist girişi". Eski üreteçte ATT&CK'te bulunmayan aile adları: Play, Rhysida, BlackByte (atlanır).
10. `requirements.txt`'e `jinja2`, `python-multipart`, `pytest` eklenmeli.

---

## 7. Frontend — durum

**Hiçbir ekran yazılmadı** (Jinja2 sürümü). Yapılacak ekranlar ve kaynak görseller:

| Ekran | Rota | Görsel | Temel bileşenler |
|---|---|---|---|
| Giriş | `/login` | — | Kullanıcı/parola |
| Genel Bakış | `/` | genel_bakis_* | 4 KPI (Toplam IOC, Aktif aktör, Zararlı ailesi, Yüksek riskli IOC), risk halka grafiği, IOC tipi dağılımı, 30 gün eklenen IOC, son istihbarat tablosu, kaynak senkronizasyonu, en çok görülen ATT&CK teknikleri |
| IOC Araştırma | `/iocs` | genel_bakis_* | Filtreler (tip, önem, güven aralığı, kaynak, tarih), sıralama, sayfalama, tek tıkla kopyala, sağda IOC detay paneli, detay sayfası `/iocs/{id}` |
| İlişki Grafi | `/graph` | genel_bakis_* | vis-network; zoom +/−, sığdır, sıfırla, düğüm tipi filtresi, derinlik 1/2/3 (varsayılan 2), düğüm sınırı + çift tıkla genişlet, düğüm detayı ve **kenar detayı (kanıt)**, grafın altında erişilebilir ilişki tablosu, iki aktör arası en kısa yol |
| Tehdit Aktörleri | `/actors` | tehdit_aktorleri.png | Liste + sağ detay paneli (alias, profil, kampanyalar, zararlılar, teknikler, benzer aktörler) |
| Kampanyalar | `/campaigns` | kampanyalar.png | Liste + sağ detay |
| Zararlı Yazılımlar | `/malware` | (görselde yok, şartnamede varlık olarak var) | Liste + detay |
| MITRE ATT&CK | `/attack` | mitre_attack.png | Taktik kartları, matris görünümü, teknik tablosu, sağ detay |
| Veri Kaynakları | `/sources` | veri_kaynaklari.png | Kaynaklar, iş geçmişi (eklenen/güncellenen/atlanan/hatalı), dosya içe aktarma (katı mod seçeneği), iş hata satırları |
| Denetim Kayıtları | `/audit` | denetim_kayitlari.png | Tablo + önce/sonra farkı |
| Ayarlar | `/settings` | ayarlar.png | Kullanıcılar ve roller (gerçek CRUD), rol yetki matrisi (salt bilgi), risk skoru formülü açıklaması, entegrasyon durumu (`.env`'de anahtar var mı) |

Tasarım belirteçleri (şartname): arka plan `#0B1020`, kenar çubuğu `#0F172A`, kart `#111A2E`, yükseltilmiş yüzey `#18243B`, mor `#7C5CFC`, camgöbeği `#22D3EE`, metin `#F1F5F9`, ikincil metin `#94A3B8`, kritik `#F87171`, yüksek `#FB923C`, orta `#FBBF24`, düşük `#34D399`. Düğüm renkleri: IOC camgöbeği, zararlı mor, kampanya amber, aktör kırmızı, ATT&CK tekniği yeşil.

Erişilebilirlik (şartname §9): semantik HTML, aria-label, klavye gezinimi, görünür odak, rengin tek anlam taşıyıcısı olmaması, grafiklerin metinsel özeti, mobilde kenar çubuğu çekmeceye dönüşür, tablolarda yatay kaydırma.

Öneri (eski prototipten): üst barda **"SQL"** düğmesi → o sayfanın çalıştırdığı gerçek SQL'leri gösteren çekmece (`GET /api/trace/{id}`, `X-Trace-Id` başlığı). Sunumda "ORM yok, bakın sorgu bu" demek için çok değerli. Kod: `_archive/react-prototype/src/components/SqlDrawer.tsx`.

---

## 8. Yapılan testler ve sonuçları

| Test | Sonuç |
|---|---|
| `pytest tests/test_normalize.py` (Python 3.13, bulut) | **34/34 geçti** |
| `python -m py_compile` + `pyflakes` (app, importers) | Hata yok (ama §6'daki mantıksal uyumsuzluklar derleme hatası vermez) |
| `importers/build_attack_snapshot.py` gerçek STIX dosyasıyla | Başarılı (sayılar §5.5) |
| SQL betiklerinin SQL Server'da çalıştırılması | **YAPILMADI.** Bulut ortamında SQL Server kurulamadı |
| API uç noktaları | **Çalıştırılmadı** |
| Arayüz | **Yok** |
| abuse.ch / CISA canlı istekleri | Yapılmadı (bulut ağında urlhaus.abuse.ch engelliydi) |

---

## 9. Karşılaşılan sorunlar

1. Bulut ortamında SQL Server çalıştırılamadı: `packages.microsoft.com`, `mcr.microsoft.com` ve Docker Hub vekil sunucuda engelli, Docker servisi yok. **Bu yüzden T-SQL hiç çalıştırılmadı; ilk çalıştırmada sözdizimi hataları beklenmeli.**
2. GitHub kimlik bilgisi geçersizdi (`gh auth`), depo oluşturulamadı.
3. abuse.ch API'lerinin hepsi (ThreatFox, MalwareBazaar, URLhaus) artık ücretsiz **Auth-Key** istiyor (https://auth.abuse.ch), `Auth-Key` HTTP başlığıyla. ThreatFox `get_iocs` en fazla 7 gün. MalwareBazaar'da `get_file` (dosya indirme) **kullanılmamalı**. URLhaus için `https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{n}/` uç noktası kullanıldı ama resmi sayfada bu yol doğrulanamadı; ilk denemede kontrol edin. Anahtar yoksa içe aktarıcılar "atlandı" der, uygulama çalışmaya devam eder.
4. MATCH'in yalnızca SELECT'te desteklendiği öğrenildi → eşitleme ve tetikleyiciler buna göre yeniden tasarlandı (§5.3).
5. `services/importer.py`'de operatör önceliği hatası (`a or b if c else d`) bulundu ve düzeltildi.
6. ATT&CK aktör ülke çıkarımı ilk sürümde hedef ülkeleri köken sanıyordu (ör. Kimsuky → KR); yalnızca ilk cümleye bakacak şekilde düzeltildi.

---

## 10. Bundan sonraki geliştirme sırası

**Adım 0 — Git (kullanıcının bilgisayarında)**
```powershell
cd C:\Users\fatih\Github\threat-intelligence-platform
git init -b main
git add . && git commit -m "ThreatLens: veritabani katmani, servisler, devir belgesi"
gh repo create threat-intelligence-platform --private --source . --push   # veya GitHub web arayüzünden
```
Takım arkadaşlarını depoya ortak çalışan olarak ekleyin.

**Adım 1 — Veritabanını gerçek SQL Server'da ayağa kaldır (en kritik adım)**
1. SQL Server 2022 Developer + SSMS + "ODBC Driver 18 for SQL Server" kurulu olmalı.
2. Önce `scripts/setup_db.py`'yi §6 madde 8'e göre düzelt.
3. `python -m venv .venv && .venv\Scripts\activate && pip install -r requirements.txt`
4. `.env.example` → `.env`, sunucu adını yaz.
5. `python scripts/setup_db.py` → her `.sql` dosyası sırayla çalışır, hata veren yığını ve ilk satırını yazar. Hataları tek tek düzelt (§5.3'teki 5 varsayıma özellikle dikkat).
6. ATT&CK yüklemesinden sonra `EXEC dbo.sp_CheckGraphConsistency;` her satırda `IsConsistent = 1` vermeli.
7. `database/demos/*.sql` dosyalarını SSMS'te çalıştırıp beklenen sonuçları doğrula.

**Adım 2 — Demo verisi:** `importers/demo_data.py` (§6 madde 9). `python -m importers demo`.

**Adım 3 — Backend'i yeni şemaya uyarla** (§6 madde 1–7, 10). Şartnamedeki uç nokta listesi: `docs/design-references/SARTNAME_ThreatLens_prompt.txt` §5.

**Adım 4 — Frontend** (§7): önce `base.html` (kenar çubuğu, üst bar, arama, kullanıcı menüsü, responsive çekmece) + `static/css/app.css` + `static/js/core.js` (fetch, tablo, sayfalama, toast, kopyala, panel), sonra sırasıyla Genel Bakış → IOC Araştırma → İlişki Grafi → Aktörler → Kampanyalar → ATT&CK → Veri Kaynakları → Denetim → Ayarlar → Zararlı Yazılımlar. vis-network, Chart.js, Lucide ve yazı tiplerini `app/static/vendor/` altına indir. 1440/1024/390 px ekran görüntüleriyle kontrol et.

**Adım 5 — Testler:** `tests/test_api.py` (veritabanı yoksa `pytest.skip`): giriş, rol yetkileri (izleyici yazamaz → 403), IOC ekle → AuditLog satırı, tekrar ekleme → 409/400, eşzamanlılık (eski RowVer → 400 mesaj 50009), katı modda hatalı içe aktarma → gösterge sayısı değişmez, graf tutarlılığı.

**Adım 6 — Belgeler (`docs/`):** proje amacı ve kapsamı, gereksinim analizi, **Chen ER diyagramı** (draw.io; ekip derste bu formatta çiziyor), ilişkisel şema, **normalizasyon raporu (en az 5 örnek, 4 adımlı; 26 Kasım teslim)**, SQL Graph mimarisi, nesne listesi, roller, API, kurulum (`README.md`), test senaryoları, örnek sorgular, performans karşılaştırması, ekran görüntüleri, sunum demo akışı. Bilinçli türetilmiş nitelik: `Indicator.NormalizedValue` (raporda gerekçesiyle anlatılmalı); graf kenarlarındaki Confidence/EvidenceID ilişkisel ara tabloların yansımasıdır (bilinçli denormalizasyon).

**Adım 7 — Gerçek beslemeler:** abuse.ch anahtarı alınınca `python -m importers threatfox malwarebazaar urlhaus feodo kev`.

---

## 11. Uyulması gereken kurallar (devralan için)

- Mevcut dosyaları silmeyin; `_archive/` referanstır.
- Veritabanında veri kaybettirecek işlem yapmayın; `setup_db.py --reset` yalnızca kullanıcı açıkça isterse.
- Kanıtlanmamış ilişkiyi gerçek veri gibi üretmeyin. Sentetik veri her zaman **DEMO DATA** kaynağında ve "demo" etiketli olmalı.
- Gerçekte çalıştırılmamış bir testi başarılı gibi raporlamayın.
- Tüm SQL parametreli (`?`), ORM yok.
