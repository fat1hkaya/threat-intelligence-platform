# ThreatLens: Tehdit İstihbaratı Platformu

BLM3001 Veri Tabanı Yönetim Sistemleri dersi projesi. Microsoft SQL Server (ilişkisel model + **SQL Graph**) üzerinde çalışan, FastAPI + Jinja2 arayüzlü bir Threat Intelligence Platform (TIP).

Bir IOC'nin (IP, domain, URL, MD5/SHA-1/SHA-256) yalnızca kaydını değil, **zararlı yazılım → kampanya → tehdit aktörü → MITRE ATT&CK tekniği** zincirindeki ilişkilerini, her ilişkinin **kanıtı ve kaynağıyla** gösterir. İlişkiler veritabanında `AS NODE` / `AS EDGE` tablolarında saklanır ve `MATCH` / `SHORTEST_PATH` ile sorgulanır.

- **ORM yok:** Tüm veritabanı erişimi elle yazılmış, parametreli T-SQL (`pyodbc`). Arayüzdeki **SQL** düğmesi o ekranın çalıştırdığı gerçek sorguları gösterir.
- **Uydurma veri yok:** Veritabanındaki her IOC gerçek bir kaynaktan (CISA KEV, abuse.ch Feodo Tracker / ThreatFox / MalwareBazaar / URLhaus) ya da bir analistin girişinden gelir. Gösterge paneli sayıları canlı sorgulardan hesaplanır; sentetik (demo) veri yoktur.

## Ekranlar

| Ekran | Ne yapar |
|---|---|
| Genel bakış | KPI'lar, önem/tip dağılımı, son N günde eklenen IOC'ler, son istihbarat, kaynak durumu, en çok kullanılan ATT&CK teknikleri |
| IOC araştırma | Tip/önem/kaynak/durum/güven aralığı/tarih filtresi, sıralama, sayfalama, tek tıkla kopyalama, toplu kontrol, detay paneli, IOC ekleme |
| IOC detayı | Atıf zinciri (MATCH), çok adımlı kill chain, görülmeler, değişiklik geçmişi, düzenleme (iyimser eşzamanlılık), kanıtlı ilişki ekleme |
| İlişki grafı | vis-network; derinlik 1/2/3, düğüm sınırı, tür filtresi, çift tıkla genişletme, düğüm ve **kenar (kanıt) detayı**, erişilebilir ilişki tablosu, aktörler arası **SHORTEST_PATH** |
| Tehdit aktörleri / Kampanyalar / Zararlı yazılımlar | Liste + detay paneli (takma adlar, araçlar, teknikler, atfedilen IOC'ler, benzer aktörler, zaman çizelgesi) |
| MITRE ATT&CK | Taktik kartları, teknik tablosu, matris görünümü (aktör/kampanya/zararlı işaretleme), teknik detayı |
| Veri kaynakları | Kaynak sağlığı, içe aktarma işleri (eklenen/güncellenen/atlanan/hatalı), dosyadan içe aktarma (katı mod = ROLLBACK), hata satırları |
| Denetim kayıtları | Tetikleyicilerin yazdığı değişmez denetim izi, günlük grafik, önceki/yeni değer karşılaştırması |
| Ayarlar | Kullanıcı ve rol yönetimi, rol yetki matrisi, risk skoru formülü, veritabanı nesneleri, graf tutarlılığı, entegrasyon durumu |

Arayüz Türkçedir, 1440 / 1024 / 390 px genişliklerde test edilmiştir (mobilde kenar çubuğu çekmeceye, tablolar kart görünümüne geçer).

## Kurulum (Windows)

### 1. Gerekenler

| Bileşen | Not |
|---|---|
| SQL Server **2019 veya üzeri** (Developer önerilir) | Kenar kısıtı ve `SHORTEST_PATH` 2019+ ister. Geliştirme SQL Server **2025 Developer** üzerinde yapıldı ve test edildi. |
| ODBC Driver 18 for SQL Server | `winget install Microsoft.msodbcsql.18` |
| Python 3.12+ | 3.14 ile test edildi |

SQL Server kurulu değilse: Microsoft'un SQL Server Developer sayfasından indirip **Basic** kurulum seçin (varsayılan örnek `MSSQLSERVER`, Windows kimlik doğrulama). Not: SQL Server 2022'nin web yükleyicisi (`SQL2022-SSEI-Dev.exe`) artık "This version of the installer is no longer supported" hatası veriyor. Bu durumda 2025 Developer sürümünü kurun.

### 2. Python ortamı

```powershell
cd C:\Users\fatih\Github\threat-intelligence-platform
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
copy .env.example .env
```

`.env` içinde sunucu adı varsayılan olarak `localhost` (Express için `localhost\SQLEXPRESS`).

### 3. Veritabanı

```powershell
.venv\Scripts\python scripts\setup_db.py
```

Betik sırasıyla şunları yapar:
1. `database/*/NN_*.sql` dosyalarını numara sırasıyla çalıştırır.
2. Kullanıcıları ekler.
3. MITRE ATT&CK Enterprise v20.1 anlık görüntüsünü yükler (15 taktik, 706 teknik, 178 aktör, 842 yazılım, 57 kampanya, 19.000 kanıtlı ilişki).
4. Gerçek beslemeleri çeker: CISA KEV ve Feodo Tracker anahtarsız çalışır. `.env` dosyasında `ABUSECH_AUTH_KEY` varsa ThreatFox, MalwareBazaar ve URLhaus da çekilir. İnternet yoksa `--no-feeds` ile yalnızca ATT&CK yüklenir.
5. Graf tutarlılığını denetler.

Süre yaklaşık 20 saniye. Tekrar çalıştırmak güvenlidir; var olan tablolara dokunmaz. Baştan kurmak için `--reset` ekleyin, ama bu veritabanını **siler**.

### 4. Çalıştırma

```powershell
.venv\Scripts\python run.py
```

Tarayıcıda http://127.0.0.1:8000 adresini açın. API belgesi: http://127.0.0.1:8000/api/docs

| Kullanıcı | Rol | Parola (yalnızca yerel demo) |
|---|---|---|
| `fatih` (Fatih Kaya) | Yönetici | `ThreatLens2026!` |
| `analist` | Analist | `ThreatLens2026!` |
| `izleyici` | İzleyici | `ThreatLens2026!` |

### 5. Gerçek beslemeler (isteğe bağlı)

ThreatFox, MalwareBazaar ve URLhaus API'leri ücretsiz bir **Auth-Key** ister: https://auth.abuse.ch. Anahtarı `.env` dosyasına `ABUSECH_AUTH_KEY=...` olarak yazın. Sonra Veri Kaynakları ekranındaki **Senkronize et** düğmesini kullanın ya da şu komutu çalıştırın:

```powershell
.venv\Scripts\python -m importers threatfox malwarebazaar urlhaus feodo kev
```

Anahtar yoksa bu kaynaklar atlanır; uygulama ATT&CK, CISA KEV ve Feodo Tracker verisiyle çalışmaya devam eder. IOC sayısı az kalır, çünkü Feodo Tracker şu an yalnızca birkaç IP yayımlıyor. MalwareBazaar'dan **yalnızca hash ve aile bilgisi** alınır; zararlı dosya asla indirilmez.

## Testler

```powershell
.venv\Scripts\python -m pytest -q
```

79 test vardır ve hepsi gerçek SQL Server'da çalışır; veritabanı yoksa atlanır. Kapsadıkları:
- **Normalleştirme:** 34 test.
- **Kimlik doğrulama ve rol yetkileri:** izleyici yazma denemesinde 403 alır.
- **IOC işlemleri:**
  - Ekleme sırasında normalleştirme yapılır, denetim kaydı yazılır, graf düğümü oluşur.
  - Silme işlemi hem kaydı hem graf düğümünü kaldırır.
  - Aynı değer tekrar eklenemez.
  - Biçimi bozuk hash reddedilir.
  - Eski RowVer ile güncelleme hata 50009 verir.
  - SQL enjeksiyonu denemesi etkisiz kalır.
- **İçe aktarma:** katı mod tüm dosyayı ROLLBACK eder; esnek mod yalnızca geçerli satırları yazar.
- **Graf:**
  - Kenarlar ilişkisel tablolarla tutarlıdır.
  - MATCH atıfları doğrudur.
  - Kenar kanıtı kaynağıyla birlikte gelir.
  - APT29→FIN7 en kısa yolu 1 adımdır.
- **SQL betikleri:**
  - `database/demos` altındaki 7 demo ve örnek sorgular çalışır.
  - Yedekleme/geri yükleme senaryosu çalışır.
  - Kirli okuma ve kilit beklemesi iki oturumla gösterilir.
  - `GRANT`/`DENY` (hata 229/230) doğrulanır.

## Klasör yapısı

```
app/            FastAPI uygulaması
  api/          JSON uç noktaları (SQL sorguları burada, ekran başına okunabilir)
  services/     normalize.py (IOC normalleştirme), importer.py (CSV/JSON içe aktarma hattı)
  templates/    Jinja2 sayfaları
  static/       css, js (saf JavaScript), vendor (vis-network, Chart.js, Lucide, yazı tipleri; çevrimdışı çalışır), samples
database/       T-SQL: schema, indexes, functions, views, graph, procedures, triggers, security, seed, demos, backup
importers/      MITRE ATT&CK, abuse.ch, CISA KEV içe aktarıcıları
scripts/        setup_db.py (kurulum), gen_docs.py (belge üretimi)
tests/          pytest
docs/           proje belgeleri ve tasarım referansları
_archive/       eski React prototipi ve eski betikler (yalnızca referans)
```

## Belgeler

- [docs/01_proje_ve_mimari.md](docs/01_proje_ve_mimari.md): amaç, kapsam, gereksinimler, mimari, SQL Graph tasarımı, güvenlik
- [docs/02_normalizasyon_taslak.md](docs/02_normalizasyon_taslak.md): normalizasyon örnekleri (ekip için taslak)
- [docs/03_test_ve_demo.md](docs/03_test_ve_demo.md): test sonuçları ve 7 demo senaryosunun sunum akışı
- [docs/diyagramlar/](docs/diyagramlar/): Chen ER (Graphviz DOT) ve ilişkisel şema (Mermaid)
- [docs/veritabani_nesneleri.md](docs/veritabani_nesneleri.md) ve [docs/api.md](docs/api.md): `python scripts/gen_docs.py` ile canlı sistemden üretilir

## Veri kaynakları ve dürüstlük notları

- **MITRE ATT&CK** ilişkileri (aktör–yazılım, aktör–teknik, kampanya–aktör…) kaynaktaki açıklamalarıyla birlikte `Evidence` tablosuna yazılır.
- **Aktör köken ülkesi, motivasyonu ve hedef sektörleri** ATT&CK açıklamasından anahtar sözcükle **sezgisel** olarak çıkarılır. Emin olunamayanlar boş bırakılır.
- **Sentetik veri yoktur.** Eski sürümdeki DEMO DATA modülü kaldırıldı (`_archive/demo_data_kaldirildi.py` yalnızca referans olarak duruyor). Testler kendi IOC'lerini oluşturup test sonunda siler.
- `SHORTEST_PATH` **ağırlıksız** en kısa yolu bulur. Güven puanı yol ağırlığı olarak kullanılmaz.
