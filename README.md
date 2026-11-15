# ThreatLens: Tehdit İstihbaratı Platformu

[![CI](https://github.com/fat1hkaya/threat-intelligence-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/fat1hkaya/threat-intelligence-platform/actions/workflows/ci.yml)

BLM3001 Veri Tabanı Yönetim Sistemleri dersi projesi. Microsoft SQL Server (ilişkisel model + **SQL Graph**) üzerinde çalışan, FastAPI + Jinja2 arayüzlü bir Threat Intelligence Platform (TIP).

Bir IOC'nin (IP, domain, URL, MD5/SHA-1/SHA-256) yalnızca kaydını değil, **zararlı yazılım → kampanya → tehdit aktörü → MITRE ATT&CK tekniği** zincirindeki ilişkilerini, her ilişkinin **kanıtı ve kaynağıyla** gösterir. İlişkiler veritabanında `AS NODE` / `AS EDGE` tablolarında saklanır ve `MATCH` / `SHORTEST_PATH` ile sorgulanır.

- **ORM yok:** Tüm veritabanı erişimi elle yazılmış, parametreli T-SQL (`pyodbc`). Arayüzdeki **SQL** düğmesi o ekranın çalıştırdığı gerçek sorguları gösterir.
- **Uydurma veri yok:** Veritabanındaki her IOC gerçek bir kaynaktan (CISA KEV, abuse.ch Feodo Tracker / ThreatFox / MalwareBazaar / URLhaus, Malpedia) ya da bir analistin girişinden gelir. Gösterge paneli sayıları canlı sorgulardan hesaplanır; sentetik (demo) veri yoktur.

## Ekranlar

| Ekran | Ne yapar |
|---|---|
| Genel bakış | KPI'lar (indexed view'dan), önem/tip dağılımı, son N günde eklenen IOC'ler, son istihbarat, kaynak durumu, en çok kullanılan ATT&CK teknikleri |
| Arama | Tüm varlıklarda tek kutudan arama; kanıt metinlerinde **tam metin arama** (FREETEXTTABLE, kurulu değilse LIKE) |
| IOC araştırma | Tip/önem/kaynak/durum/güven aralığı/tarih filtresi, sıralama, sayfalama, toplu kontrol, detay paneli, IOC ekleme |
| IOC detayı | Atıf zinciri (MATCH), kill chain, **açıklanabilir risk skoru**, **zaman yolculuğu** (temporal tablo), ağ bilgisi (ASN, /24 komşuları), STIX dışa aktarımı, vakaya ekleme |
| Log avı | Yapıştırılan/yüklenen logdaki IP, domain, URL ve hash'leri bilinen IOC'lerle tek set tabanlı sorguda eşleştirir (retro-hunt); eşleşmeler görülme olarak kaydedilebilir |
| Vakalar | Soruşturma çalışma alanı: varlıklar SQL Graph kenarıyla vakaya bağlanır, notlar, durum, **ortak bağlantı önerisi**, vaka grafı, STIX 2.1 paketi |
| İlişki grafı | vis-network; derinlik 1/2/3, düğüm sınırı, tür filtresi, çift tıkla genişletme, kenar (kanıt) detayı, aktörler arası **SHORTEST_PATH**, vaka modu |
| Altyapı | IP IOC'lerinin /24 alt ağ, ASN ve ülke bazında kümelenmesi: farklı ailelerin paylaştığı barındırma altyapısı |
| Tehdit aktörleri / Kampanyalar / Zararlı yazılımlar | Liste + detay paneli; ATT&CK Navigator katmanı ve STIX 2.1 dışa aktarımı |
| MITRE ATT&CK | Taktik kartları, teknik tablosu, matris görünümü, **tespit kapsamı** (kör noktalar, aktör bazında yüzde, ilişkisel bölme) |
| Veri kaynakları | Kaynak sağlığı, içe aktarma işleri, dosyadan içe aktarma (katı mod = ROLLBACK), hata satırları, elle senkron |
| Denetim kayıtları | Tetikleyicilerin yazdığı değişmez denetim izi, giriş denemeleri, günlük grafik, önceki/yeni değer karşılaştırması |
| Ayarlar | Kullanıcı ve rol yönetimi, IOC saklama politikası, Query Store en pahalı sorgular, veritabanı nesneleri, graf tutarlılığı |

## Öne çıkan veritabanı özellikleri

| Özellik | Nerede |
|---|---|
| SQL Graph: `AS NODE`/`AS EDGE`, çok bağlantılı kenar kısıtı, `MATCH`, `SHORTEST_PATH` | `database/graph`, vaka kenarı `19_investigations.sql` |
| Application Role (`sp_setapprole`): sorgular kullanıcının rolünün GRANT/DENY sınırında çalışır | `08_security.sql`, `app/db.py` |
| Temporal tablolar: IOC'nin geçmişteki herhangi bir andaki hâli | `16_temporal.sql` |
| Indexed view (`WITH NOEXPAND`), nonclustered columnstore, Query Store | `17_performance.sql` |
| Tam metin arama (FREETEXTTABLE / CONTAINS) | `18_fulltext.sql` |
| Satır içi tablo değerli fonksiyonla açıklanabilir risk skoru | `03_functions.sql` (`fn_RiskBreakdown`) |
| İlişkisel bölme (çift `NOT EXISTS`): tüm teknikleri kapsanan aktörler | `15_coverage.sql` |
| IP aralığı araması: `TOP (1) ... ORDER BY StartIP DESC` ile tek indeks araması | `20_network.sql` |
| SQL Server Agent işleri: süresi dolan IOC'ler, graf bakımı | `10_lifecycle.sql`, `11_agent_jobs.sql` |
| Tetikleyicilerle denetim izi, graf senkronu, ağ zenginleştirme | `07_triggers.sql` ve migration'lar |

Arayüz Türkçedir; 390 / 768 / 1024 / 1440 / 1920 / 2560 px genişliklerde ölçülerek test edilmiştir (yatay taşma yok, JavaScript hatası yok):
- **Mobil:** kenar çubuğu çekmeceye, tablolar iki sütunlu kartlara geçer; filtreler "Filtreler (n)" düğmesiyle açılır, fazla eylemler "Diğer" menüsüne taşınır; dokunma hedefleri en az 44 px.
- **Tema:** koyu, açık ve sistem teması (kullanıcı menüsünden); graf tuvali ve SQL kod blokları iki temada da koyu kalır. Metin kontrastı her iki temada WCAG AA (en az 4,5:1).
- **Tablolar:** sıkı/rahat görünüm, IOC listesinde filtrelerle CSV ve engelleme listesi (.txt) dışa aktarma.
- **Graf:** teknikler tek kümede toplanır, kenar etiketleri yakınlaştırınca görünür, seçilen düğümün komşuları vurgulanır, türe göre katmanlı yerleşim seçilebilir.

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

Diğer kaynaklar:

| Komut | Kaynak | Not |
|---|---|---|
| `python -m importers malpedia` | Malpedia (CC BY-SA 4.0) | Zararlı ailesi diğer adları ve aile → aktör atıfları; besleme adlarını tek aileye birleştirir |
| `python -m importers ip2asn` | iptoasn.com (Public Domain, PDDL v1.0) | Yaklaşık 500 bin IPv4 aralığı → ASN ve ülke; IOC üretmez, IP IOC'lerini zenginleştirir (yönetici) |

`scripts/sync_feeds.cmd`, Windows Görev Zamanlayıcı ile 6 saatte bir beslemeleri senkronize eder (`logs/sync_feeds.log`).

## Testler

```powershell
.venv\Scripts\python -m pytest -q
```

133 test vardır ve gerçek SQL Server'da çalışır; veritabanı yoksa atlanır. GitHub Actions her push'ta aynı testleri SQL Server 2025 Linux kapsayıcısında çalıştırır (`.github/workflows/ci.yml`; beslemeler indirilmez, tam metin arama kapsayıcıda kurulu olmadığı için LIKE yedeği sınanır). Kapsadıkları:
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
- **İleri özellikler:**
  - Saklama politikası ve süresi dolan IOC işi; giriş kilitleme (5 hatalı deneme / 15 dk → 429); parola değişimi.
  - Risk skoru Python ile aynı sonucu verir; temporal tabloda geçmiş hâl doğru gelir.
  - Log avı birebir, URL ana bilgisayarı ve üst domain eşleşmelerini bulur.
  - Tespit kapsamında alt teknik devralma ve ilişkisel bölmenin Python küme hesabıyla aynı sonucu vermesi.
  - Vaka öğelerinin MATCH ile doğrulanması, kapalı vakaya ekleme reddi, varlık silinince kenarın CASCADE ile silinmesi.
  - STIX 2.1 paketlerinin yapısal doğrulaması (`tests/stix_check.py`), Navigator katmanı biçimi.
  - IPv4 → tamsayı dönüşümü, tetikleyiciyle ağ zenginleştirme ve aralık araması.
- **SQL betikleri:**
  - `database/demos` altındaki 8 demo ve örnek sorgular çalışır.
  - Yedekleme/geri yükleme senaryosu çalışır.
  - Kirli okuma ve kilit beklemesi iki oturumla gösterilir.
  - `GRANT`/`DENY` (hata 229/230) doğrulanır.

## Klasör yapısı

```
app/            FastAPI uygulaması
  api/          JSON uç noktaları (SQL sorguları burada, ekran başına okunabilir)
  services/     normalize.py (IOC normalleştirme), importer.py (CSV/JSON içe aktarma hattı), hunt.py (log ayıklama)
  templates/    Jinja2 sayfaları
  static/       css, js (saf JavaScript), vendor (vis-network, Chart.js, Lucide, yazı tipleri; çevrimdışı çalışır), samples
database/       T-SQL: schema, indexes, functions, views, graph, procedures, triggers, security, seed,
                migrations (10-20: yaşam döngüsü, Agent işleri, kimlik doğrulama, log avı, kapsama,
                temporal, performans, tam metin, vakalar, ağ), demos, backup
importers/      MITRE ATT&CK, abuse.ch, CISA KEV, Malpedia, iptoasn.com içe aktarıcıları
scripts/        setup_db.py (kurulum), gen_docs.py (belge üretimi), sync_feeds.cmd (zamanlanmış senkron)
.github/        CI iş akışı (SQL Server kapsayıcısında pytest, JS sözdizimi)
tests/          pytest
docs/           proje belgeleri ve tasarım referansları
_archive/       eski React prototipi ve eski betikler (yalnızca referans)
```

## Belgeler

- [docs/01_proje_ve_mimari.md](docs/01_proje_ve_mimari.md): amaç, kapsam, gereksinimler, mimari, SQL Graph tasarımı, güvenlik
- [docs/02_normalizasyon_taslak.md](docs/02_normalizasyon_taslak.md): normalizasyon örnekleri (ekip için taslak)
- [docs/03_test_ve_demo.md](docs/03_test_ve_demo.md): test sonuçları ve 8 demo senaryosunun sunum akışı
- [docs/diyagramlar/](docs/diyagramlar/): Chen ER (Graphviz DOT) ve ilişkisel şema (Mermaid)
- [docs/veritabani_nesneleri.md](docs/veritabani_nesneleri.md) ve [docs/api.md](docs/api.md): `python scripts/gen_docs.py` ile canlı sistemden üretilir

## Veri kaynakları ve dürüstlük notları

- **MITRE ATT&CK** ilişkileri (aktör–yazılım, aktör–teknik, kampanya–aktör…) kaynaktaki açıklamalarıyla birlikte `Evidence` tablosuna yazılır.
- **Aktör köken ülkesi, motivasyonu ve hedef sektörleri** ATT&CK açıklamasından anahtar sözcükle **sezgisel** olarak çıkarılır. Emin olunamayanlar boş bırakılır.
- **Sentetik veri yoktur.** Eski sürümdeki DEMO DATA modülü kaldırıldı (`_archive/demo_data_kaldirildi.py` yalnızca referans olarak duruyor). Testler kendi IOC'lerini oluşturup test sonunda siler.
- `SHORTEST_PATH` **ağırlıksız** en kısa yolu bulur. Güven puanı yol ağırlığı olarak kullanılmaz.
- **Tespit kapsamı** kurumun kendi beyanıdır; başlangıçta boştur, uydurma kapsama verisi yüklenmez.
- IP aralığının **ülkesi barındırma yeridir**, saldırganın kökeni değildir.
- **USOM** listesi eklenmedi: `.txt` paylaşımı 1 Haziran 2026'da sona erdi, yerine gelen API'nin belgesi ve kullanım koşulları yayımlanmadı.
