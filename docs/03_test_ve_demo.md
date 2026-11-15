# Testler ve sunum demo akışı

## 1. Otomatik testler

```powershell
.venv\Scripts\python -m pytest -q
```

Son sonuç: **133 test geçti, 0 başarısız**. Ortam: SQL Server 2025 Developer 17.0.1000.7, Python 3.14 (15 Kasım 2026). Aynı testler GitHub Actions'ta SQL Server 2025 Linux kapsayıcısında da çalışır (`.github/workflows/ci.yml`).

| Dosya | Test | Doğrulanan |
|---|---:|---|
| `test_normalize.py` | 34 | IPv4/IPv6/domain/URL/hash/e-posta normalleştirme ve defang çözümü |
| `test_hunt_extract.py` | 6 | Log ayıklama: defang çözümü, URL ana bilgisayarı ve üst domain adayları, dosya uzantısı eleme |
| `test_api.py` | 61 | Giriş, 401/403, Application Role sınırları (sp_setapprole), giriş kilitleme (429), parola değişimi, IOC yaşam döngüsü + denetim + graf düğümü, RowVer eşzamanlılığı, SQL enjeksiyonu, içe aktarma, graf tutarlılığı, MATCH, SHORTEST_PATH, saklama politikası ve süresi dolan IOC işi, Malpedia ad birleştirme, risk skoru (Python ile aynı sonuç), log avı, tespit kapsamı ve ilişkisel bölme, temporal sürümler ve geçmiş hâl, tam metin arama, indexed view sayıları, Query Store yetkisi, vaka yaşam döngüsü ve CASCADE |
| `test_exports.py` | 6 | ATT&CK Navigator katmanı biçimi, STIX 2.1 paketlerinin yapısal doğrulaması (`tests/stix_check.py`), belirlenimci kimlikler, vaka = grouping |
| `test_network.py` | 11 | IPv4 → tamsayı dönüşümü, ip2asn ayrıştırıcı, tetikleyiciyle zenginleştirme, `TOP (1)` aralık araması, /24 komşuları, yönetici yetkisi |
| `test_sql_scripts.py` | 15 | Demo 1–8 betikleri, örnek sorgular, yedekleme/geri yükleme, kirli okuma ve kilit zaman aşımı, kayıp güncellemenin önlenmesi, GRANT/DENY (229 ve 230), CISA KEV MERGE, zararlı ailesi birleştirme ve ad anahtarıyla eşleme |

Testlerin yakaladığı ve düzeltilen hatalar:

| Hata | Düzeltme |
|---|---|
| Demo 5: `CAST(ROW_NUMBER())` NULL olabilir sütun üretiyordu, PRIMARY KEY eklenemiyordu | `ISNULL(..., 0)` kullanıldı ve `ALTER TABLE` ayrı yığına alındı |
| Yedekleme betiği var olmayan `C:\SQLBackup\` klasörüne yazmaya çalışıyordu | Yollar artık `SERVERPROPERTY('InstanceDefaultBackupPath')` değerinden okunuyor |
| `/api/tactics`: toplama fonksiyonu içinde alt sorgu kullanılmıştı | CTE ile yeniden yazıldı |
| ODBC sürücüsü `SHORTEST_PATH(...{1,6})` ifadesini bozuyordu | Bağlantıda `SQL_ATTR_NOSCAN` açıldı |
| CISA KEV içe aktarıcısında `FROM @changes` eksikti, içe aktarma hiç çalışmıyordu | Düzeltildi; ağa çıkmadan SQL'i sınayan test eklendi |
| Tetikleyicisi olan tablolarda `INTO`'suz `OUTPUT` yasak (hata 334): kayıt oluşturan uçlar 500 veriyordu | `Db.insert_id` çıktıyı tablo değişkenine yazıyor |
| Application Role etkinken ODBC bağlantı havuzu oturumu bozuyordu | ODBC havuzu kapatıldı; rol başına ayrı uygulama havuzu |
| `sp_InvestigationRemoveItem`: alt sorgulu `CASE` ifadesi `$to_id` ile karşılaştırılınca hiç eşleşmiyordu | Düğüm kimlikleri önce değişkene alınıyor |
| Feodo IOC'leri her senkronda etkin/süresi dolmuş arasında gidip geliyordu | Yalnızca yeni bitiş tarihi gelecekteyse yeniden etkinleştiriliyor |
| `setup_db.py` çıktı yönlendirilince cp1254 kod sayfası "⊂" yazamayıp çöküyordu | stdout UTF-8'e ayarlanıyor |

Elle yapılan tarayıcı kontrolleri: ilk 11 sayfa 1440 / 1024 / 390 px genişlikte açıldı. JavaScript hatası çıkmadı ve yatay taşma görülmedi (tek taşma 390 px'deki IOC detayındaydı, düzeltildi).

Tarayıcıda yapılmayan kontroller:
- Ekran okuyucuyla deneme.
- abuse.ch ThreatFox / MalwareBazaar / URLhaus canlı beslemeleri (anahtar gerekiyor).

CISA KEV (1781 zafiyet) ve Feodo Tracker canlı olarak çekildi ve içe aktarıldı.

Bu sonuncular için Veri Kaynakları ekranındaki "Senkronize et" düğmesini kullanın.

## 2. Sunum demo akışı (şartname §10)

Her demo hem arayüzden hem SSMS'ten gösterilebilir. Arayüzde her ekranın sağ üstündeki **SQL** düğmesi, o ekranın çalıştırdığı gerçek T-SQL'i gösterir.

### Demo 1: SHA-256 → zararlı → kampanya → aktör
- **Arayüz:**
  1. İlişki grafı ekranında örnek düğmelerinden birine basın (ör. "IPv4 → QakBot → …") ya da bir IOC yapıştırın.
  2. Düğüme tıklayıp ayrıntılara bakın.
  3. Kenara tıklayıp kanıtı ve kaynağı görün.
  4. Düğüme çift tıklayarak komşularını ekleyin.
- **SQL:** `database/demos/demo1_hash_investigation.sql`.
- **Beklenen:** Özet bir aileye (`IndicatesMalware`) bağlıdır. Aile bir aktöre (`ActorUsesMalware`), aktör de tekniklere bağlıdır. Kill chain satır döndürür.
- **Not:** IOC–aile bağlantısı kaynağın beyanıdır (ör. Feodo Tracker "bu IP QakBot C2'sidir" der); aile–aktör bağlantısı MITRE ATT&CK'ten gelir. Kenara tıklayınca her ilişkinin kaynağı ayrı ayrı görünür.

### Demo 2: Aktörün ATT&CK teknikleri
- **Arayüz:** Tehdit aktörleri ekranında APT29'a tıklayın. Panelde teknikler taktiğe göre gruplanmış görünür. "ATT&CK matrisinde göster" düğmesi tekniklerini çerçeveli olarak işaretler.
- **SQL:** `demo2_actor_techniques.sql` (`fn_ActorTechniques`, GROUP BY, MATCH + kanıt, `sp_AttackMatrix`).

### Demo 3: Analist IOC ekler, denetim kaydı oluşur
- **Arayüz:**
  1. `analist` ile giriş yapın.
  2. IOC araştırma ekranında "Yeni IOC" düğmesine basın ve `hxxp://login-verify[.]example/a` yazın; değer normalleştirilerek kaydedilir.
  3. Denetim kayıtları ekranına geçin. "Ekleme" satırı görünür ve kullanıcı SOC Analisti'dir.
  4. IOC'yi düzenleyin; panelde önceki ve yeni değerler yan yana gösterilir.
- **SQL:** `demo3_analyst_audit.sql`. Son adımda denetim kaydını silme denemesi 50020 hatası verir.

### Demo 4: Hatalı dosya, hata kaydı ve ROLLBACK
- **Arayüz:**
  1. Veri kaynakları ekranında `ornek_hatali.csv` örneğini indirin.
  2. "Katı mod" seçili olarak içe aktarın. Sonuç: durum Hatalı, eklenen 0, ROLLBACK uyarısı; IOC sayısı değişmez.
  3. Aynı dosyayı katı mod kapalıyken tekrar yükleyin. Sonuç: durum Kısmi, geçerli satırlar eklenir, 3 hatalı satır nedenleriyle listelenir.
- **SQL:** `demo4_import_rollback.sql`.

### Demo 5: İndeksli ve indekssiz sorgu
- **SSMS:**
  1. `demo5_index_performance.sql` dosyasını açın.
  2. Önce Ctrl+M ile "Include Actual Execution Plan" seçeneğini açın.
  3. Betiği çalıştırın. 500.000 satırlık geçici tablo oluşturulur ve çalışma sonunda silinir.
- **Karşılaştırma:**
  - İndekssiz sorgu Clustered Index Scan kullanır ve binlerce logical read yapar.
  - İndeksli sorgu Index Seek kullanır ve birkaç logical read yapar.
  - Öndeki joker karakter (`LIKE '%…'`) indeksi işe yaramaz hâle getirir.

### Demo 6: Eşzamanlılık
- **SSMS:** İki pencere açıp `demo6_concurrency.sql` adımlarını izleyin. Gösterilenler:
  - READ COMMITTED kilitte bekler.
  - READ UNCOMMITTED kirli okuma yapar.
  - ROLLBACK sonrası eski değer okunur.
- **Arayüz:** Aynı IOC'nin düzenleme formunu iki sekmede açıp sırayla kaydedin. İkinci kayıt "başka bir kullanıcı tarafından değiştirildi" uyarısıyla reddedilir (RowVer).
- **Otomatik test:** `test_demo6_dirty_read_and_blocking`, `test_rowversion_lost_update_prevented`.

### Demo 7: MATCH ile çok adımlı sorgu ve SHORTEST_PATH
- **Arayüz:** İlişki grafı ekranında "Aktörler arası en kısa yol" kutusuna APT29 → FIN7 girin. Sonuç 1 adımdır; ortak araçlar AdFind, Cobalt Strike ve Mimikatz'tır. APT28 → Lazarus Group için yol bulunmaz.
- **SQL:** `demo7_graph_match.sql`. Üç adımlı MATCH deseni ile aynı sorunun 6 JOIN'li ilişkisel karşılığı aynı sonucu verir; bu testle doğrulandı.

### Demo 8: İleri veritabanı özellikleri (`demo8_advanced_features.sql`)
SSMS'te gerçek yürütme planı açıkken: `LIKE '%phish%'` ile `CONTAINS`/`FREETEXTTABLE` karşılaştırması, `COUNT(*) GROUP BY` ile indexed view (`WITH NOEXPAND`), columnstore'lu ve columnstore'suz denetim analizi, bir IOC'nin temporal sürümleri ve 1 saat önceki hâli, Query Store'dan en pahalı sorgular.

### Ek demolar (arayüzden)
- **Log avı:** Log Avı → "Örnek log yükle" → Avla. Gerçek IOC'ler içeren log satırları birebir, URL ana bilgisayarı ve üst domain eşleşmesiyle bulunur; SQL çekmecesinde tek `sp_RetroHunt` çağrısı görünür.
- **Vaka:** bir IOC detayında "Vakaya ekle" → yeni vaka; aktör panelinden aynı vakaya ekleyin. Vaka detayında "Ortak bağlantılar" vakadaki iki öğeye birden bağlı varlıkları önerir; "Vaka grafı" ve "STIX 2.1" düğmeleri.
- **Tespit kapsamı:** ATT&CK → Kapsama görünümü; teknik detayında düzey işaretleyin, aktör yüzdesi ve kör noktalar değişir; "Navigator'a aktar" katman dosyasını indirir (https://mitre-attack.github.io/attack-navigator/ adresinde açılır).
- **Zaman yolculuğu:** IOC detayında güveni değiştirin, "Bu tarihteki hâli" ile önceki değeri görün (`FOR SYSTEM_TIME AS OF`).
- **Altyapı:** aynı /24 alt ağı paylaşan farklı zararlı aileleri (ör. 17 IOC'lu 31.57.216.0/24).

### Ek: yedekleme ve geri yükleme
- `database/backup/backup_restore.sql`: BACKUP (COMPRESSION, CHECKSUM), RESTORE VERIFYONLY, FILELISTONLY ve farklı adla RESTORE … MOVE adımlarını içerir. Ardından satır sayısı karşılaştırılır ve kopya silinir.
- Yedek dosyası SQL Server'ın varsayılan yedek klasörüne yazılır.

## 3. Örnek sorgular

`database/demos/sample_queries.sql` içinde S1–S23 sorguları vardır:
- JOIN, anti-join, GROUP BY/HAVING, EXISTS, INTERSECT/EXCEPT, ilişkisel bölme, self join
- RANK/PARTITION, kümülatif toplam, PIVOT, özyinelemeli CTE
- UPDATE…FROM, TRY/CATCH
- MATCH, SHORTEST_PATH ve tutarlılık sorguları

Hepsi testte hatasız çalıştı.
