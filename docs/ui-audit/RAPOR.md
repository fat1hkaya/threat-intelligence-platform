# ThreatLens arayüz/UX iyileştirme raporu

Görev: `docs/CLAUDE_CODE_UI_PROMPT.md` (proje sahibinin yerel görev belgesi, depoda değil). Beş aşama, her biri ayrı commit (aşama 4 büyüklüğü nedeniyle üç parça):

| Aşama | Commit |
|---|---|
| 1 · Veri doğruluğu ve test izolasyonu | `UI: aşama 1 — veri doğruluğu ve test izolasyonu` |
| 2 · Tasarım sistemi ve ortak bileşenler | `UI: aşama 2 — tasarım sistemi ve ortak bileşenler` |
| 3 · Duyarlı düzen | `UI: aşama 3 — duyarlı düzen` |
| 4 · Sayfa sayfa değişiklikler | `UI: aşama 4 (1/3)`, `(2/3)`, `(3/3)` |
| 5 · Son kontrol | `UI: aşama 5 — son kontrol ve rapor` |

Durum işaretleri: **✓** yapıldı · **kısmen** bir bölümü yapıldı (neden yazılı) · **yapılmadı** (neden yazılı).

---

## 1. Otomatik denetim: önce / sonra (§2)

`python scripts/ui_screenshots.py <before|after>`; 1440×790 birincil hedef. Değerler tüm sayfaların toplamıdır (`önce → sonra`). Sayfa sayısı arttı: denetim aşama 4'te Denetim kayıtları ve Ayarlar sekmelerini de kapsayacak biçimde genişletildi.

| Görünüm | Sayfa | Yatay taşma | Kenar çubuğu kaydırması | İzinsiz iç kaydırma | İpucusuz kesik metin | Çakışan metin | Konsol hatası |
|---|---|---|---|---|---|---|---|
| `primary` 1440×790 | 24 → 28 | 0 → **0** | 0 → **0** | 13 → **0** | 72 → **0** | 11 → **0** | 0 → **0** |
| `wide` 1920×1000 | 24 → 28 | 0 → **0** | 0 → **0** | 6 → **0** | 70 → **0** | 0 → **0** | 0 → **0** |
| `laptop` 1280×720 | 24 → 28 | 0 → **0** | 23 → **0** | 18 → **0** | 75 → **0** | 70 → **0** | 0 → **0** |
| `tablet` 1024×768 | 24 → 28 | 0 → **0** | 23 → **0** | 17 → **0** | 77 → **0** | 57 → **0** | 0 → **0** |
| `mobile` 390×844 | 24 → 28 | 0 → **0** | 0 → **0** | 10 → **0** | 80 → **0** | 78 → **0** | 0 → **0** |

İzin verilen kaydırma alanları (sayılmaz): sağ detay paneli ve pencere gövdesi (§4.2), ATT&CK matrisi ve dar ekranda geniş tablolar (yatay, yapışkan ilk sütun ve sağ kenar gölgesiyle, §4.2).

## 2. Erişilebilirlik (§7.3)

Lighthouse için Node.js kurulu olmadığından **Playwright + axe-core 4.10.2** kullanıldı (proje sahibinin onayıyla; dosya yalnızca `scripts/vendor/axe.min.js` altında, uygulama yüklemez, MPL-2.0). `python scripts/a11y_audit.py after --all`; kurallar WCAG 2.1 A/AA + en iyi uygulamalar, 1440×790, koyu ve açık tema. Puan, Lighthouse'a benzer biçimde uygulanabilir kuralların etkiye göre ağırlıklı ortalamasıdır (kritik 10, ciddi 7, orta 3, küçük 1). Sonuçların tamamı: [`after/a11y.json`](after/a11y.json).

| Tema | Sayfa | Puan | Kritik | Ciddi | İhlal kuralı |
|---|---|---|---|---|---|
| Koyu | login | **100** | 0 | 0 | 0 |
| Koyu | overview | **100** | 0 | 0 | 0 |
| Koyu | iocs | **100** | 0 | 0 | 0 |
| Koyu | graph-hash | **100** | 0 | 0 | 0 |
| Koyu | tüm 26 sayfa | en düşük **100** | 0 | 0 | 0 |
| Açık | login | **100** | 0 | 0 | 0 |
| Açık | overview | **100** | 0 | 0 | 0 |
| Açık | iocs | **100** | 0 | 0 | 0 |
| Açık | graph-hash | **100** | 0 | 0 | 0 |
| Açık | tüm 26 sayfa | en düşük **100** | 0 | 0 | 0 |

Bu aşamada giderilen ihlaller: avatar ve seçili bölümlü düğmelerde beyaz metin kontrastı (mor ton koyulaştırıldı), açık temada "Yüksek" rozeti kontrastı, grafiklerde `role="img"` için erişilebilir ad, ilişki tablosu özet satırında iç içe etkileşimli öğe, sekmelerde izinsiz `aria-pressed`, yetki matrisi simgelerinde `role="img"`, matris sütun başlığı düzeyi, sayfa yolu bağlantısının yalnızca renkle ayrılması.

## 3. Madde madde durum

### §3 Aşama 1 — Veri doğruluğu ve test izolasyonu
| Madde | Durum | Not |
|---|---|---|
| 3.1 Test veritabanı ayrımı | ✓ | `ThreatLens_Test` (`TL_DB_NAME_TEST`); conftest oturum başında `setup_db` ile kurar; `tests/test_zz_live_guard.py` canlı satır sayılarını başta ve sonda karşılaştırır; CI güncellendi. |
| 3.2 Kirlilik temizleme betiği | ✓ | `scripts/purge_test_artifacts.py`: varsayılan rapor, `--apply` ile tek işlemde siler, `AuditLog`'a dokunmaz. |
| 3.3 Denetimdeki eski test satırları | ✓ | Proje sahibi iki seçeneği de seçti: (a) `docs/sunum_oncesi_kontrol.md`, (b) "Otomasyon kayıtlarını gizle" (varsayılan açık, veri silinmez). |
| 3.4 Yer tutucu aileler | ✓ | `Malware.IsPlaceholder` elle bakılan bir bayrak yerine **hesaplanmış** sütun (`fn_IsPlaceholderMalware`; ATT&CK kaydı olanlar hariç). "Ailesi belirlenmemiş" etiketi, istatistiklerden ve listeden varsayılan hariç, "Yer tutucuları göster" filtresi. |
| 3.5 Aile sınıflandırması ve ATT&CK eşlemesi | kısmen | Eşleşmeyen besleme aileleri "Sınıflandırılmamış", takma ad (ThreatFox `malware_alias`) ve Malpedia kimliği eşleme adayı, "ATT&CK ile eşleşmedi" etiketi yapıldı. Eşleşme sayısının önce/sonra karşılaştırması o aşamada kaydedilmedi; bugünkü durum: 1.026 ailenin 842'si ATT&CK kimlikli, 184'ü Sınıflandırılmamış, aktöre bağlanan IOC sayısı 1.852. |
| 3.6 Terim tutarlılığı | ✓ | "Yüksek önemli" = önem yüksek/kritik; "yüksek riskli" = `RiskBand` eşiği; dikkat kartı "· 24 saat" der. |
| 3.7 Kaynaklarda birim | ✓ | `vw_SourceUnit`: zafiyet, teknik, IP aralığı, aile, IOC. |
| 3.8 Önem dağılımı | ✓ | Risk bandı dağılımı (sıfırlar dahil), eşikler `RiskBand` tablosundan. |
| 3.9 Giriş ipucu | ✓ | `TL_LOGIN_HINT` varsayılanı kapalı. |

### §4 Aşama 2 — Tasarım sistemi
| Madde | Durum | Not |
|---|---|---|
| 4.1 Belirteçler | ✓ | Yoğunluk 40/52 px, boşluk ve tipografi ölçeği, kırmızı yalnızca kritik/hata. |
| 4.2 Kaydırma davranışı | ✓ | Tek ana kaydırma, 4 satır kırpma + "Devamını göster", ince tema çubukları, `scrollbar-gutter`. |
| 4.3 Kenar çubuğu | ✓ | Üç grup, 1440×790'da kaydırmasız, seçili ve üzerine gelme ayrık. |
| 4.4 Üst çubuk ve kullanıcı menüsü | ✓ | |
| 4.5 Tablo bileşeni | ✓ | Ortadan kısaltma, sabit kopyalama düğmesi, sütun önceliği + "Sütunlar", sayfa boyutu, toplu seçim, 768 px altında kart listesi. |
| 4.6 Filtre araç çubuğu | ✓ | Tek satır, kendiliğinden uygulanır, etiketler, adres çubuğunda durum, çift uçlu kaydırıcı, telefonda alt panel. |
| 4.7 Detay paneli | ✓ | Sınır §5 tablosuna göre ≥1280 px yanda (§4.7'de 1440 yazıyordu; iki bölüm çelişiyordu, §5 izlendi). |
| 4.8 Pencereler ve formlar | ✓ | |
| 4.9 Durumlar | ✓ | |
| 4.10 Geliştirici modu | ✓ | `.tech` / `.user-only`; Ayarlar'da Veritabanı sekmesi. |

### §5 Aşama 3 — Duyarlı düzen
| Madde | Durum | Not |
|---|---|---|
| Kırılım tablosu | ✓ | 236/224 px kenar çubuğu, 1024–1279 ikon şeridi, ≤1023 ☰; panel yanda / çekmece / tam ekran. |
| Kart içi `@container` | ✓ | Yalnızca çubuk, halka, anahtar-değer ve zincir içeren kartlarda (her kartta açmak açılır menüleri keserdi). |
| KPI sırası, `align-items: start` | ✓ | |
| Mobil: yapışkan eylem, alt panel, tablo öncelikli graf, 44 px | ✓ | |
| Kabul ölçütleri | ✓ | Bölüm 1'deki tablo. |

### §6 Aşama 4 — Sayfa sayfa
| Madde | Durum | Not |
|---|---|---|
| 6.1 Giriş | ✓ | Tek yüzey form, Caps Lock, "Giriş yapılıyor…", kilitte kalan dakika ve süre dolana kadar kapalı düğme, yeni alt başlık. |
| 6.2 Genel bakış | kısmen | Dikkat kartları, KPI, yatay eksen (en çok 6), kaydırmasız son istihbarat, kaynak rozetleri ve "+5 yeni · toplam", ayrı teknik kodu yapıldı. **"İlk içe aktarma" işareti** koşula bağlı ve gösterilmiyor: beslemeler IOC'leri kaynaktaki ilk görülme tarihiyle getirdiği için ilk içe aktarmadan önceki günler boş değil. |
| 6.3 IOC araştırma | ✓ | §6.3 öncelikleri, sayı önde 48 px güven çubuğu, panelde "Tam sayfada aç" (panel ≥1280 px). |
| 6.4 IOC detayı | ✓ | Atıf zinciri en üstte, her halkada kanıt ve kaynak; Vakaya ekle, Görülme ekle, Grafikte aç, Durumu değiştir; alan bazında önce/sonra geçmişi. |
| 6.5 Log avı | kısmen | Sonuç paneli, satır konumu vurgusu, Vakaya ekle, eşleşmeyen göstergeler, tanınmayan satır sayısı, turuncu/nötr rozetler, 80 ch, ikincil "Temizle" yapıldı. "Tümünü gör" API'nin döndürdüğü son 30 avı gösterir (eski avlar için sayfalama yok). Eşleşmeyen göstergeler yalnızca av anında hesaplanır; geçmiş bir avı açınca listelenmez. |
| 6.6 Vakalar | ✓ | Sekme sayıları, 3 adımlık boş durum, iş akışı düğmesi, Varlık ekle, etkinlik akışı (durum değişiklikleri denetim kaydından okunur), Markdown rapor, küçük ortak bağlantılar. |
| 6.7 İlişki grafı | ✓ | Yönlü gezinme (teknik/zafiyet yaprak, ters yön yalnızca başlangıcın komşuları, tip başına sınır ve "+N" küme düğümü), derinlik 2, asıl yol vurgusu ve %35 çapraz kenarlar, sınır bilgi satırı, katmanlı yerleşim varsayılan, kenar etiketleri gizli, tek satır kontrol çubuğu ve otomatik tamamlama, düğme çipler, gruplu/sayfalı ilişki tablosu, "belirtilmemiş" güven, daraltılabilir en kısa yol, risk ipucu. Gezinme `sp_GetNeighborhood` değiştirilmeden `app/api/graph.py` içinde parametreli sorgularla yapılır. En kısa yol bulununca yol ayrı bir grafikte vurgulu çizilir (açık grafın içinde değil). |
| 6.8 Altyapı | ✓ | Başlıklı IOC sütunu, nötr aile sayısı, 3 çip + N, tek satır ASN, kısa ülke adı. |
| 6.9 Tehdit aktörleri | ✓ | |
| 6.10 Kampanyalar | ✓ | "Süren" = bitiş yok ya da son 90 gün. |
| 6.11 Zararlı yazılımlar | ✓ | |
| 6.12 MITRE ATT&CK | ✓ | 5×3 taktik ızgarası ve açık ifade, yapışkan başlık şeridi, kaydırma göstergesi, ısı lejantı, kapsam başlangıç ekranı, matriste işaretleme, Navigator katmanı içe aktarma (önce sayım), sayfalı kör noktalar. |
| 6.13 Veri kaynakları | kısmen | Düzen, Dosya içe aktar penceresi, ayrı sütunlar, ikon senkron düğmesi ve satır menüsü, satırda senkron göstergesi, iş tablosu, "Yalnızca değişiklik olanlar" yapıldı. İşin hata satırları yan panel yerine **pencerede** açılır. |
| 6.14 Denetim kayıtları | ✓ | Üç sekme, dört KPI (yığılmış dağılım çubuğu, hatalı giriş), işlem türüne göre yığılmış grafik ve 7/30/90 gün, tek satır kullanıcı, önce/sonra paneli, giriş denemelerinde kilitlenme filtresi ve sayfalama. |
| 6.15 Ayarlar | ✓ | Sekmeler; onaylı rol değişikliği, kendi rolünü değiştirememe, satır menüsü; yaşam döngüsünde kaydedilmemiş değişiklik göstergesi ve Kaydet; 9 kaynağın tamamı ve bağlantı testi; gruplu bakım işleri; SQL tek satır + Göster, araç/sistem sorguları süzülür. Risk bandı eşikleri gösterilir, arayüzden düzenlenmez (görevde istenmedi). |

### §7 Aşama 5 — Son kontrol
| Madde | Durum | Not |
|---|---|---|
| 7.1 `after` ekran görüntüleri | ✓ | 5 görünüm × 28 sayfa (vaka detayı için bölüm 5); `primary` ve `report.json` depoda, diğer görünümler `.gitignore`'da (yerelde). |
| 7.2 Bu rapor | ✓ | |
| 7.3 Erişilebilirlik ≥90, kritik 0 | ✓ | Lighthouse yerine axe-core (gerekçe bölüm 2'de). |
| 7.4 Testler ve canlı veritabanı koruması | ✓ | 164 test geçti (canlı veritabanı koruma testi dahil). |
| 7.5 PROJECT_HANDOFF.md ve README.md | ✓ | |

### §8 Korunan iyi yanlar
Kenar kanıtı ve ağırlıksız en kısa yol notu, boş graf ekranında örnek zincirler, ilişki tablosu, "SQL Server bağlı" göstergesi ve daraltılabilir kenar çubuğu, Türkçe sayı/tarih biçimi, düğüm renk + şekil ayrımı (ilişki tablosunda da şekil ikonu), IOC düğüm paneli eylemleri, "barındırma yeri ≠ köken" ve "sezgisel çıkarım" notları, benzer aktörler, STIX 2.1 / Navigator dışa aktarımları, risk skoru açıklama kartı: hepsi yerinde.

---

## 4. Ekran görüntüleri: `primary` (1440×790) önce / sonra

| Sayfa | Önce | Sonra |
|---|---|---|
| actors | [önce](before/primary/actors.png) | [sonra](after/primary/actors.png) |
| actors-panel | [önce](before/primary/actors-panel.png) | [sonra](after/primary/actors-panel.png) |
| attack-coverage | [önce](before/primary/attack-coverage.png) | [sonra](after/primary/attack-coverage.png) |
| attack-list | [önce](before/primary/attack-list.png) | [sonra](after/primary/attack-list.png) |
| attack-matrix | [önce](before/primary/attack-matrix.png) | [sonra](after/primary/attack-matrix.png) |
| audit | [önce](before/primary/audit.png) | [sonra](after/primary/audit.png) |
| audit-logins | — | [sonra](after/primary/audit-logins.png) |
| audit-runs | — | [sonra](after/primary/audit-runs.png) |
| campaigns | [önce](before/primary/campaigns.png) | [sonra](after/primary/campaigns.png) |
| campaigns-panel | [önce](before/primary/campaigns-panel.png) | [sonra](after/primary/campaigns-panel.png) |
| case-detail | [önce](before/primary/case-detail.png) | [sonra](after/primary/case-detail.png) |
| cases | [önce](before/primary/cases.png) | [sonra](after/primary/cases.png) |
| graph-empty | [önce](before/primary/graph-empty.png) | [sonra](after/primary/graph-empty.png) |
| graph-hash | [önce](before/primary/graph-hash.png) | [sonra](after/primary/graph-hash.png) |
| hunt | [önce](before/primary/hunt.png) | [sonra](after/primary/hunt.png) |
| infrastructure | [önce](before/primary/infrastructure.png) | [sonra](after/primary/infrastructure.png) |
| ioc-detail | [önce](before/primary/ioc-detail.png) | [sonra](after/primary/ioc-detail.png) |
| ioc-lookup-dialog | [önce](before/primary/ioc-lookup-dialog.png) | [sonra](after/primary/ioc-lookup-dialog.png) |
| ioc-new-dialog | [önce](before/primary/ioc-new-dialog.png) | [sonra](after/primary/ioc-new-dialog.png) |
| iocs | [önce](before/primary/iocs.png) | [sonra](after/primary/iocs.png) |
| login | [önce](before/primary/login.png) | [sonra](after/primary/login.png) |
| malware | [önce](before/primary/malware.png) | [sonra](after/primary/malware.png) |
| malware-panel | [önce](before/primary/malware-panel.png) | [sonra](after/primary/malware-panel.png) |
| overview | [önce](before/primary/overview.png) | [sonra](after/primary/overview.png) |
| settings | [önce](before/primary/settings.png) | [sonra](after/primary/settings.png) |
| settings-integrations | — | [sonra](after/primary/settings-integrations.png) |
| settings-maintenance | — | [sonra](after/primary/settings-maintenance.png) |
| settings-risk | — | [sonra](after/primary/settings-risk.png) |
| sources | [önce](before/primary/sources.png) | [sonra](after/primary/sources.png) |

## 5. Bilinen sınırlamalar

- **Canlı veritabanına yazan iki yeni akış tarayıcıda denenmedi:** ATT&CK matrisinde tıklayarak kapsama işaretleme ve Navigator katmanı içe aktarma, proje sahibinin kapsam beyanını değiştireceği için canlıda çalıştırılmadı. İçe aktarma, yalnızca sayım yapan (`dryRun`) bir API testiyle doğrulandı.
- **Erişilebilirlik denetimi** pencereleri (Yeni IOC, Toplu kontrol) kapsamaz; sayfaların kendisini denetler. Puan Lighthouse'un birebir aynısı değildir, aynı ağırlıklandırma mantığıyla axe sonuçlarından hesaplanır.
- **Telefonda tam sayfa ekran görüntüleri** alt kenara sabitlenen birincil düğmeyi ("Yeni IOC") sayfanın ortasında gösterir; bu, tam sayfa yakalamanın bir sonucudur, gerçek cihazda düğme alt kenardadır.
- **Bağlantı testi** yalnızca kaynağın sunucusuna erişimi dener (HEAD); abuse.ch anahtarının geçerliliğini sınamaz.
- **Ekran denetimi betikleri** (`ui_screenshots.py`, `a11y_audit.py`) giriş yaptığı için canlı `LoginAttempt` / `UserSession` tablolarına satır ekler; pytest ile aynı anda çalıştırılırsa canlı veritabanı koruma testi başarısız olur.
- **Vaka detayı** son denetim turunda yer almıyor (28 sayfa): canlı veritabanındaki tek vaka (#63) 23.11.2026 12:07'de `fatih` hesabıyla uygulamadan silindi, bu yüzden betik vaka detayı sayfasını atladı. `after/primary/case-detail.png` aynı günün ilk `after` turundan (silinmeden önce) kalmıştır.
- Denetim kaydındaki eski test satırları silinemez (bilinçli tasarım); "Otomasyon kayıtlarını gizle" yalnızca görünümden çıkarır. Tamamen temiz bir sunum için `docs/sunum_oncesi_kontrol.md` içindeki temiz kurulum yolu.
