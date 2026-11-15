# Testler ve sunum demo akışı

## 1. Otomatik testler

```powershell
.venv\Scripts\python -m pytest -q
```

Son sonuç: **79 test geçti, 0 başarısız**. Ortam: SQL Server 2025 Developer 17.0.1000.7, Python 3.14. Test, `setup_db.py --reset` ile sıfırdan kurulmuş veritabanında çalıştırıldı (15 Kasım 2026).

| Dosya | Test | Doğrulanan |
|---|---:|---|
| `test_normalize.py` | 34 | IPv4/IPv6/domain/URL/hash/e-posta normalleştirme ve defang çözümü |
| `test_api.py` | 34 | Giriş, 401/403, IOC yaşam döngüsü + denetim + graf düğümü, tekrar kaydı, hatalı değerler, RowVer eşzamanlılığı, SQL enjeksiyonu, görülme, katı/esnek içe aktarma, graf tutarlılığı, MATCH atfı, kenar kanıtı, SHORTEST_PATH, kanıtsız ilişkinin reddi, gösterge paneli sayılarının veritabanıyla eşitliği, 10 sayfanın açılması, SQL izi |
| `test_sql_scripts.py` | 11 | Demo 1–5 ve 7 betikleri, örnek sorgular, yedekleme/geri yükleme, iki oturumla kirli okuma ve kilit zaman aşımı, RowVer ile kayıp güncellemenin önlenmesi, GRANT/DENY (hata 229 ve 230) |

Testlerin yakaladığı ve düzeltilen hatalar:

| Hata | Düzeltme |
|---|---|
| Demo 5: `CAST(ROW_NUMBER())` NULL olabilir sütun üretiyordu, PRIMARY KEY eklenemiyordu | `ISNULL(..., 0)` kullanıldı ve `ALTER TABLE` ayrı yığına alındı |
| Yedekleme betiği var olmayan `C:\SQLBackup\` klasörüne yazmaya çalışıyordu | Yollar artık `SERVERPROPERTY('InstanceDefaultBackupPath')` değerinden okunuyor |
| `/api/tactics`: toplama fonksiyonu içinde alt sorgu kullanılmıştı | CTE ile yeniden yazıldı |
| ODBC sürücüsü `SHORTEST_PATH(...{1,6})` ifadesini bozuyordu | Bağlantıda `SQL_ATTR_NOSCAN` açıldı |

Elle yapılan tarayıcı kontrolleri: 11 sayfa 1440 / 1024 / 390 px genişlikte açıldı. JavaScript hatası çıkmadı ve yatay taşma görülmedi (tek taşma 390 px'deki IOC detayındaydı, düzeltildi).

Tarayıcıda yapılmayan kontroller:
- Ekran okuyucuyla deneme.
- abuse.ch canlı beslemeleri (anahtar yok).
- CISA KEV canlı çekimi.

Bu sonuncular için Veri Kaynakları ekranındaki "Senkronize et" düğmesini kullanın.

## 2. Sunum demo akışı (şartname §10)

Her demo hem arayüzden hem SSMS'ten gösterilebilir. Arayüzde her ekranın sağ üstündeki **SQL** düğmesi, o ekranın çalıştırdığı gerçek T-SQL'i gösterir.

### Demo 1: SHA-256 → zararlı → kampanya → aktör
- **Arayüz:**
  1. İlişki grafı ekranında "Hash → …" örnek düğmesine basın (ya da bir SHA-256 yapıştırın).
  2. Düğüme tıklayıp ayrıntılara bakın.
  3. Kenara tıklayıp kanıtı ve kaynağı görün.
  4. Düğüme çift tıklayarak komşularını ekleyin.
- **SQL:** `database/demos/demo1_hash_investigation.sql`.
- **Beklenen:** Özet bir aileye (`IndicatesMalware`) bağlıdır. Aile bir aktöre (`ActorUsesMalware`), aktör de tekniklere bağlıdır. Kill chain satır döndürür.
- **Not:** IOC–aile bağlantıları DEMO DATA'dır; arayüz bunu pembe rozetle belirtir.

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
